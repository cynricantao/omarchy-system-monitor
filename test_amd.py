"""AMD telemetry against a synthetic sysfs tree; no GPU required."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import backend as b


class AmdTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.drm = Path(self.temp.name)
        self.patch = patch.object(b, 'DRM', self.drm)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def device(self, card='card0', vendor='0x1002', driver='amdgpu'):
        device = self.drm / card / 'device'
        device.mkdir(parents=True)
        (device / 'vendor').write_text(vendor)
        (device / 'device').write_text('0x744c\n')
        (device / 'driver').symlink_to(self.drm / 'drivers' / driver)
        return device

    def hwmon(self, device):
        hw = device / 'hwmon' / 'hwmon0'
        hw.mkdir(parents=True)
        (hw / 'name').write_text('amdgpu\n')
        return hw

    def test_metrics_and_units(self):
        device = self.device()
        (device / 'product_name').write_text('AMD Radeon Test\n')
        for name, value in {'gpu_busy_percent': 42, 'mem_info_vram_used': 1048576,
                            'mem_info_vram_total': 8388608}.items():
            (device / name).write_text(str(value))
        hw = self.hwmon(device)
        for name, value in {'temp1_input': 55000, 'power1_average': 125500000,
                            'fan1_input': 1200, 'fan1_max': 3000}.items():
            (hw / name).write_text(str(value))
        result = b.amd_gpu()
        self.assertTrue(result['available'])
        self.assertEqual(len(result['cards']), 1)
        self.assertEqual(result['name'], 'AMD Radeon Test')
        for key, value in {'percent': 42, 'used': 1048576, 'total': 8388608,
                           'temperature': 55, 'power': 125.5, 'fan': 40}.items():
            self.assertEqual(result[key], value)

    def test_missing_invalid_and_zero_values(self):
        device = self.device()
        (device / 'gpu_busy_percent').write_text('0')
        (device / 'mem_info_vram_used').write_text('not supported')
        (device / 'mem_info_vram_total').write_text('-1')
        hw = self.hwmon(device)
        (hw / 'power1_input').write_text('0')
        (hw / 'fan1_input').write_text('0')
        (hw / 'fan1_max').write_text('0')
        result = b.amd_gpu()
        self.assertTrue(result['available'])
        self.assertEqual(result['name'], 'AMD GPU (0x744c)')
        self.assertEqual(result['percent'], 0)
        self.assertEqual(result['power'], 0)
        for key in ['used', 'total', 'temperature', 'fan']:
            self.assertIsNone(result[key])

    def test_device_filtering_and_multiple_cards(self):
        self.device('card0-DP-1')
        self.device('card1', vendor='0x8086', driver='i915')
        self.device('card2', driver='radeon')
        self.assertFalse(b.amd_gpu()['available'])
        self.device('card3')
        self.device('card4')
        self.assertEqual(len(b.amd_gpu()['cards']), 2)

    def test_unreadable_metrics_are_unavailable(self):
        self.device()
        original = b.read

        def read(path):
            if Path(path).name == 'gpu_busy_percent':
                raise PermissionError('denied')
            return original(path)

        with patch.object(b, 'read', side_effect=read):
            result = b.amd_gpu()
        self.assertTrue(result['available'])
        self.assertIsNone(result['percent'])

    def test_dispatch_keeps_nvidia_and_falls_back_to_amd(self):
        self.device()
        nvidia = dict(available=True, name='NVIDIA Test')
        with patch.object(b, 'nvidia_gpu', return_value=nvidia), patch.object(b, 'amd_gpu') as amd:
            self.assertEqual(b.gpu(), nvidia)
            amd.assert_not_called()
        for error in ['GPU telemetry unavailable', 'NVIDIA telemetry unavailable']:
            unavailable = dict(available=False, error=error)
            with patch.object(b, 'nvidia_gpu', return_value=unavailable):
                self.assertTrue(b.gpu()['available'])
                with patch.object(b, 'amd_gpu', return_value=dict(available=False, cards=[])):
                    self.assertEqual(b.gpu(), unavailable)


if __name__ == '__main__':
    unittest.main()
