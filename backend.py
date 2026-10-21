#!/usr/bin/env python3
"""Read-only, stdlib system sampler. JSON lines; stdin: open / close."""
import csv
import glob
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

PROC = Path('/proc')
DRM = Path('/sys/class/drm')
HZ = os.sysconf('SC_CLK_TCK')
PAGE = os.sysconf('SC_PAGE_SIZE')

def read(path):
    return Path(path).read_text()

def cpu_counters():
    result = {}
    for line in read(PROC / 'stat').splitlines():
        fields = line.split()
        if fields and fields[0].startswith('cpu'):
            values = list(map(int, fields[1:9]))  # guest already included in user/nice
            result[fields[0]] = (sum(values), values[3] + values[4])
    return result

def cpu_percent(old, new):
    total = new[0] - old[0]
    return round(max(0, min(100, 100 * (total - (new[1] - old[1])) / total)), 1) if total > 0 else None

def memory():
    m = {}
    for line in read(PROC / 'meminfo').splitlines():
        key, value = line.split(':', 1)
        m[key] = int(value.split()[0]) * 1024
    total = m['MemTotal']
    used = total - m['MemAvailable']
    return dict(total=total, used=used, available=m['MemAvailable'], percent=round(used / total * 100, 1), swap_total=m['SwapTotal'], swap_used=m['SwapTotal']-m['SwapFree'])

def number(value):
    try:
        return float(value)
    except ValueError:
        return None

def nvidia_gpu():
    if not os.access('/usr/bin/nvidia-smi', os.X_OK):
        return dict(available=False, error='GPU telemetry unavailable')
    try:
        p = subprocess.run(['/usr/bin/nvidia-smi', '--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,fan.speed', '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=1.5)
        if p.returncode:
            raise ValueError('NVIDIA telemetry unavailable')
        cards = []
        for row in csv.reader(p.stdout.splitlines(), skipinitialspace=True):
            name, util, used, total, temp, power, fan = row
            cards.append(dict(name=name, percent=number(util), used=None if number(used) is None else number(used)*1048576, total=None if number(total) is None else number(total)*1048576, temperature=number(temp), power=number(power), fan=number(fan)))
        return dict(available=bool(cards), cards=cards, **(cards[0] if cards else {}))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return dict(available=False, error='NVIDIA telemetry unavailable')

def sysfs_number(path, scale=1):
    try:
        value = int(read(path))
        return value / scale if value >= 0 else None
    except (OSError, ValueError):
        return None

def amd_gpu():
    cards = []
    for card in sorted(DRM.glob('card[0-9]*')):
        if not card.name[4:].isdigit():
            continue  # skip connector entries such as card0-DP-1
        device = card / 'device'
        try:
            if read(device / 'vendor').strip() != '0x1002' or (device / 'driver').resolve().name != 'amdgpu':
                continue
            try:
                name = read(device / 'product_name').strip()
            except OSError:
                name = 'AMD GPU (' + read(device / 'device').strip() + ')'
        except OSError:
            continue
        temperature = power = fan = None
        for hw in sorted((device / 'hwmon').glob('hwmon*')):
            try:
                if read(hw / 'name').strip() != 'amdgpu':
                    continue
            except OSError:
                continue
            temperature = sysfs_number(hw / 'temp1_input', 1000)
            power = sysfs_number(hw / 'power1_average', 1000000)
            if power is None:
                power = sysfs_number(hw / 'power1_input', 1000000)
            rpm, maximum = sysfs_number(hw / 'fan1_input'), sysfs_number(hw / 'fan1_max')
            if rpm is not None and maximum:
                fan = round(min(100, rpm / maximum * 100), 1)
            break
        cards.append(dict(name=name, percent=sysfs_number(device / 'gpu_busy_percent'),
                          used=sysfs_number(device / 'mem_info_vram_used'),
                          total=sysfs_number(device / 'mem_info_vram_total'),
                          temperature=temperature, power=power, fan=fan))
    return dict(available=bool(cards), cards=cards, **(cards[0] if cards else {}))

def gpu():
    nvidia = nvidia_gpu()
    if nvidia['available']:
        return nvidia
    amd = amd_gpu()
    return amd if amd['available'] else nvidia

def network():
    result = {}
    for line in read(PROC / 'net/dev').splitlines()[2:]:
        name, fields = line.split(':')
        if name.strip() != 'lo':
            f = fields.split()
            result[name.strip()] = (int(f[0]), int(f[8]))
    return result

def disks():
    rows = []
    for line in read(PROC / 'diskstats').splitlines():
        f = line.split()
        if len(f) >= 14 and Path('/sys/block', f[2]).exists() and not f[2].startswith(('loop', 'ram', 'zram')):
            rows.append((f[2], int(f[5])*512, int(f[9])*512))
    return {name: (r, w) for name, r, w in rows}

def rates(old, new, elapsed):
    return [dict(name=k, read=round(max(0, v[0]-old.get(k, v)[0])/elapsed), write=round(max(0, v[1]-old.get(k, v)[1])/elapsed)) for k, v in new.items()]

def parse_stat(text):
    end = text.rfind(')')
    pid, comm = text[:end+1].split(' (', 1)
    f = text[end+2:].split()
    return dict(pid=int(pid), comm=comm[:-1], ppid=int(f[1]), ticks=int(f[11])+int(f[12]), start=int(f[19]), rss=max(0, int(f[21]))*PAGE)

def process_records():
    result = {}
    for path in PROC.iterdir():
        if not path.name.isdigit():
            continue
        try:
            p = parse_stat(read(path / 'stat'))
            try:
                exe = os.readlink(path / 'exe')
                p['name'] = Path(exe.removesuffix(' (deleted)')).name
            except OSError:
                p['name'] = p['comm']
            p['pss'] = None
            try:
                for line in read(path / 'smaps_rollup').splitlines():
                    if line.startswith('Pss:'):
                        p['pss'] = int(line.split()[1])*1024
                        break
            except OSError:
                pass
            result[p['pid']] = p
        except (OSError, ValueError, IndexError):
            pass  # processes can exit between reads
    return result

def app_name(p, records):
    # Helpers with their own executables belong to the nearest browser/app parent.
    if p['rss'] == 0 and p['pss'] is None:
        return 'Kernel threads' if p['ppid'] == 2 or p['pid'] == 2 else p['name']
    known = ('vivaldi', 'chromium', 'firefox', 'discord', 'spotify', 'code', 'telegram', 'steam', 'chrome', 'electron')
    current = p
    seen = set()
    for _ in range(32):
        if current['pid'] in seen:
            break
        seen.add(current['pid'])
        name = current['name'].lower()
        for app in known:
            if 'crashpad' not in name and (name == app or name.startswith(app + '-') or name.startswith(app + '_') or (app == 'steam' and name == 'steamwebhelper')):
                return app.capitalize() if app != 'code' else 'VS Code'
        current = records.get(current['ppid'])
        if current is None:
            break
    return p['name']

def group_processes(records, previous, elapsed, cores):
    groups = {}
    for p in records.values():
        name = app_name(p, records)
        g = groups.setdefault(name, dict(name=name, cpu=0.0, memory=0, rss=0, pss=0, count=0, rss_fallback=0))
        old = previous.get(p['pid'])
        if old and old['start'] == p['start']:
            g['cpu'] += max(0, p['ticks']-old['ticks'])/HZ/elapsed/cores*100
        # btop's Linux process list reads RSS from stat. Preserve both
        # definitions from the same process set instead of conflating them.
        g['rss'] += p['rss']
        g['memory'] += p['rss']
        if p['pss'] is not None:
            g['pss'] += p['pss']
        g['rss_fallback'] += p['pss'] is None and p['rss'] > 0
        g['count'] += 1
    for g in groups.values():
        g['cpu'] = round(g['cpu'], 2)
        if g['rss_fallback']:
            g['pss'] = None  # partial PSS is unknown, never silently RSS
    return sorted(groups.values(), key=lambda g: (-g['cpu'], -g['memory'], g['name']))

def sensors():
    result = []
    for hw in glob.glob('/sys/class/hwmon/hwmon*'):
        try:
            chip = read(Path(hw)/'name').strip()
        except OSError:
            continue
        if chip.startswith('nvidia'):
            continue
        for path in glob.glob(hw + '/temp*_input'):
            try:
                temp = int(read(path))/1000
                label = Path(path.replace('_input', '_label'))
                name = read(label).strip() if label.exists() else chip
                if -20 <= temp <= 150:
                    result.append(dict(name=name, temperature=temp))
            except (OSError, ValueError):
                pass
    return result

def mounts():
    rows, seen = [], set()
    for line in read(PROC / 'mounts').splitlines():
        source, mount, fs = line.split()[:3]
        mount = mount.replace('\\040', ' ')
        if not source.startswith('/dev/') or mount in seen:
            continue
        seen.add(mount)
        try:
            s = os.statvfs(mount)
            total = s.f_blocks*s.f_frsize
            device_key = (source, total)
            if device_key in seen:
                continue
            seen.add(device_key)
            rows.append(dict(name=mount, total=total, used=(s.f_blocks-s.f_bfree)*s.f_frsize, available=s.f_bavail*s.f_frsize))
        except OSError:
            pass
    return rows

class Sampler:
    def __init__(self):
        self.cpu = cpu_counters()
        self.net = network()
        self.disk = disks()
        self.time = time.monotonic()
        self.processes = {}
        self.process_time = None
        self.history = []

    def sample(self, detailed=False):
        now = time.monotonic()
        elapsed = max(.001, now-self.time)
        cp = cpu_counters()
        mem = memory()
        card = gpu()
        net, disk = network(), disks()
        cpu = cpu_percent(self.cpu['cpu'], cp['cpu'])
        self.history = (self.history + [dict(cpu=cpu, ram=mem['percent'], gpu=card.get('percent'))])[-60:]
        result = dict(timestamp=time.time(), cpu=cpu, cores=[cpu_percent(self.cpu.get(k, v), v) for k, v in cp.items() if k != 'cpu'], memory=mem, gpu=card, network=rates(self.net, net, elapsed), disks=rates(self.disk, disk, elapsed), history=self.history, detailed=detailed, interval=2)
        if detailed:
            records = process_records()
            result.update(apps=group_processes(records, self.processes, max(.001, now-(self.process_time or now)), len(cp)-1), processes_warming=self.process_time is None, sensors=sensors(), mounts=mounts(), load=list(os.getloadavg()), uptime=float(read(PROC/'uptime').split()[0]))
            self.processes, self.process_time = records, now
        else:
            self.processes, self.process_time = {}, None
        self.cpu, self.net, self.disk, self.time = cp, net, disk, now
        return result

def main():
    sampler = Sampler()
    opened = False
    deadline = time.monotonic()+.3
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], max(0, deadline-time.monotonic()))
        if ready:
            command = sys.stdin.readline()
            if not command:
                return
            opened = command.strip() == 'open'
            deadline = min(deadline, time.monotonic())
        if time.monotonic() >= deadline:
            started = time.monotonic()
            try:
                result = sampler.sample(opened)
                result['sample_ms'] = round((time.monotonic()-started)*1000, 1)
                print(json.dumps(result, separators=(',', ':')), flush=True)
            except (OSError, ValueError) as error:
                print(json.dumps(dict(error=type(error).__name__)), flush=True)
            deadline = time.monotonic()+2

if __name__ == '__main__':
    main()
