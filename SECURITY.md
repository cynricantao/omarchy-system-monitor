# Security policy

## Trust boundary

This is a read-only monitor, **not a sandbox**. QML runs in the Omarchy shell with the logged-in user's access. The Python child inherits that access. Treat installing this plugin like executing local code: review source and trust the shell, Python, NVIDIA utilities and installed dependencies.

The collector reads `/proc` and `/sys` plus filesystem capacity via `statvfs`. It never kills processes, writes system settings or elevates privileges. External execution is fixed argv (no shell interpolation): isolated `/usr/bin/python3 -I` starts the bundled collector and `/usr/bin/nvidia-smi` runs a fixed telemetry query with a 1.5-second timeout. Fixed executable paths avoid PATH shadowing on the supported Arch/Omarchy platform; do not replace them with untrusted helpers. AMD telemetry reads the `amdgpu` device and hwmon files under `/sys/class/drm` directly; no AMD utility, sysfs writes or elevated privileges are used.

Dynamic names in dashboard labels use `Text.PlainText`, preventing rich-text markup/resource interpretation. App images select only fixed local icon paths, not process-supplied URLs. GPU output is parsed as CSV/JSON data, never evaluated as QML or commands.

## IPC exposure

The retained `open`, `close`, `toggle`, `view`, `sort`, and `memory` methods control only the monitor UI/detailed sampling. `status` exports health/selection state only, no application lists, mount paths, hardware metrics or histories. Geometry/layout/scroll debugging IPC has been removed.

Local shell IPC is unsandboxed and has no plugin-specific authorization. Processes able to access the shell's IPC socket may invoke these controls, show private information on screen or cause detailed scanning. Same-user malicious code can also read the collector/shell memory and underlying system data; this plugin cannot protect against it. Do not expose shell IPC through network bridges or shared untrusted accounts.

## Privacy and availability limitations

See the README privacy section. Process basenames, mount paths and interface labels may still be sensitive on screen. Do not attach screenshots, raw sampler output, logs or crash dumps without reviewing/redacting them. No such artifacts belong in this repository.

Kernel permission restrictions can make data unavailable. Process exits/races are handled, but arbitrarily large `/proc` trees, slow mounts, driver problems and local resource exhaustion can delay collection. The GPU timeout bounds waiting, not captured output size. No whole-sample deadline or hostile-driver isolation is promised. Keep OS/driver dependencies updated. This is not a hardened multi-user monitoring service.

## Reporting

Report vulnerabilities to GitHub user `cynricantao` through the repository's private vulnerability reporting feature **if enabled**. Do not assume that feature is available before publication. If it is unavailable, open a minimal issue asking for a private reporting channel; omit exploit details and private diagnostics. No response-time commitment is made. Only the latest repository candidate is maintained; report its version and reproduction with synthetic/redacted data.
