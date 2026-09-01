# ramview — Windows Memory Viewer

Note: the releases contain a 7-Zip self extracting archive that extract a full Python 3.14 installation as well as my program.

View raw bytes loaded in memory, either from a running process (virtual memory)
or directly from physical RAM.

Requires Python 3. No third-party packages.

## GUI

Launch the graphical front-end (same access backends, clickable):

```
python ramview_gui.py
```

- **Target** radio buttons switch between *Physical RAM* and *Process* memory.
- **Process** mode: pick a PID (auto-refreshed list), then Read, Probe, or Modules.
- **Address / Bytes** fields: hex address (`0x` prefix optional) and amount to show.
- **Read** (F3): hex-dump at the address. **Probe** (F5): list readable regions
  and the process's memory bounds (start/end address).
- Requests are auto-clamped into the process's readable memory: an address
  below its start (e.g. `0x0`) shows the start, and one past its end shows the
  end, with a note explaining the adjustment.
- **<- Prev / Next ->**: page up/down through memory.
- **Save...** (Ctrl+S): dump raw bytes to a binary file.
- Physical RAM needs the WinPmem driver (below).

## Read a process's memory (works without admin)

Find a process:

```
python ramview.py --processes
```

List the process's readable memory regions and mapped modules:

```
python ramview.py --pid <PID> --probe
```

Hex-dump memory at a virtual address:

```
python ramview.py --pid <PID> -a 0x7ff7e2950000 -s 128
```

Interactive navigation:

```
python ramview.py --pid <PID> -d
```

Dump to file:

```
python ramview.py --pid <PID> -a 0x0 -s 4096 -o dump.bin
```

## Read physical RAM (needs a kernel driver + admin)

Modern Windows blocks the `\\.\PhysicalMemory` device, so physical access needs
the [WinPmem](https://github.com/Velocidex/WinPmem) driver loaded. Run your
terminal **as Administrator**.

```
python ramview.py -a 0x0 -s 256          # first 256 bytes of physical RAM
python ramview.py -p                     # probe readable physical regions
python ramview.py -d                     # interactive physical viewer
```

### To get physical access working (verified)

1. Run the terminal as Administrator.
2. Download the official signed WinPmem Go tool from
   [Velocidex/WinPmem releases](https://github.com/Velocidex/WinPmem/releases)
   (`go-winpmem_amd64_1.0-rc2_signed.exe`). It embeds the current signed
   Binalyze kernel driver.
3. Install the driver and leave it loaded:
   ```
   go-winpmem_amd64_1.0-rc2_signed.exe install
   ```
   This creates and starts the `winpmem` service, exposing the `\\.\pmem`
   device this script reads through. Verify with `sc query winpmem` (should be
   `RUNNING`).

This script auto-detects `\\.\PhysicalMemory`, `\\.\NtPhysicalMemory`,
`\\.\WinPmem` and WinPmem's `\\.\pmem` device.

To unload the driver when done:

```
go-winpmem_amd64_1.0-rc2_signed.exe uninstall
```

Note: the older `winpmem_mini_x64_rc2.exe` imager does not reliably acquire
images on Windows 10 build 19041+ (produces 0-byte output), so the `install`
route above is the supported one.

## Help

```
python ramview.py -h
```

## Disclaimer

This is a low-level memory inspection tool. Reading protected processes and
physical RAM can trigger antivirus safeguards and may only be possible from an
elevated context. Use it only on systems/processes you are authorized to inspect.

## License
Licensed using the [`MIT License`](https://github.com/ondrejplaysgd2/ramview/blob/main/LICENSE.md).
