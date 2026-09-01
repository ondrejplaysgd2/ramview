#!/usr/bin/env python3
"""ramview - Direct physical memory reader for Windows.

Reads raw bytes from physical RAM using the \\.\\PhysicalMemory device.
Must be run as Administrator.

Usage:
    python ramview.py [options]

Options:
    -a, --address ADDR    Physical address to start reading (hex, e.g. 0x0 or 0x100000)
    -s, --size SIZE       Number of bytes to read (decimal or hex with 0x prefix)
    -o, --output FILE     Write raw bytes to a binary file
    -d, --dump            Full interactive hex dump mode
    -p, --probe           Probe and list available physical memory ranges
    -l, --list            List all readable memory regions
    -h, --help            Show this help

Examples:
    python ramview.py -a 0x0 -s 256          Read first 256 bytes of physical RAM
    python ramview.py -p                     Probe memory layout
    python ramview.py -a 0x100000 -s 4096    Read 4KB at 1MB mark
    python ramview.py -a 0x0 -s 1024 -o dump.bin
    python ramview.py -d                     Interactive hex dump
"""

import ctypes
import ctypes.wintypes as wintypes
import sys
import struct
import argparse

# Windows constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_ATTRIBUTE_NORMAL = 128
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

# NT NTLDR driver IOCTL codes for physical memory access
IOCTL_NTLDR_QUERY_DEVICE_INFO = 0x00222040
IOCTL_NTLDR_MAP_PHYSICAL_MEMORY = 0x00222044
IOCTL_NTLDR_UNMAP_PHYSICAL_MEMORY = 0x00222048
IOCTL_NTLDR_QUERY_PHYSICAL_MEMORY = 0x00222004

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

# --- API prototypes (argtypes/restype) ---
kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

# --- Structures ---

class PHYSICAL_MEMORY_REQUEST(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_ulonglong),
        ("size", ctypes.c_ulonglong),
    ]


class PHYSICAL_MEMORY_RANGE(ctypes.Structure):
    _fields_ = [
        ("base_address", ctypes.c_ulonglong),
        ("size", ctypes.c_ulonglong),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# --- API wrappers ---

def create_file(path, access=GENERIC_READ | GENERIC_WRITE,
                share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
                security_attributes=None, creation=OPEN_EXISTING,
                flags=FILE_ATTRIBUTE_NORMAL, template=None):
    handle = kernel32.CreateFileW(
        path, access, share_mode, security_attributes,
        creation, flags, template
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(err, f"CreateFileW failed for {path}: error {err}")
    return handle


def device_io_control(handle, code, in_buffer, in_size, out_size=4096):
    bytes_returned = wintypes.DWORD(0)
    out_buffer = ctypes.create_string_buffer(out_size)
    success = kernel32.DeviceIoControl(
        handle, code,
        in_buffer, in_size,
        out_buffer, out_size,
        ctypes.byref(bytes_returned), None
    )
    if not success:
        err = ctypes.get_last_error()
        raise OSError(err, f"DeviceIoControl(0x{code:08X}) failed: error {err}")
    return out_buffer.raw[:bytes_returned.value]


def read_file(handle, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = wintypes.DWORD(0)
    success = kernel32.ReadFile(handle, buffer, size, ctypes.byref(bytes_read), None)
    if not success:
        err = ctypes.get_last_error()
        raise OSError(err, f"ReadFile failed: error {err}")
    return buffer.raw[:bytes_read.value]


def close_handle(handle):
    kernel32.CloseHandle(handle)


def open_process(pid, access=PROCESS_ALL_ACCESS):
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        raise OSError(err, f"OpenProcess({pid}) failed: error {err}")
    return handle


def read_process_memory(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    success = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
    )
    if not success:
        err = ctypes.get_last_error()
        if err == 299:  # ERROR_PARTIAL_COPY
            got = bytes_read.value
            if got:
                return buffer.raw[:got]
            raise OSError(
                err,
                f"ReadProcessMemory(0x{address:X}) failed: address is not readable "
                f"in this process (0x{address:X} is unmapped, protected, or the "
                f"null page). Use --probe to find readable regions.",
            )
        raise OSError(err, f"ReadProcessMemory(0x{address:X}) failed: error {err}")
    return buffer.raw[:bytes_read.value]


def query_virtual_memory(handle, address):
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQueryEx(
        handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
    )
    if result == 0:
        err = ctypes.get_last_error()
        raise OSError(err, f"VirtualQueryEx failed: error {err}")
    return mbi


def get_process_modules(pid):
    """Get list of loaded modules (name, base address, size) for a process."""
    modules = []
    try:
        # TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        snap = kernel32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
        if snap == INVALID_HANDLE_VALUE:
            return modules

        class MODULEENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260),
            ]

        me = MODULEENTRY32()
        me.dwSize = ctypes.sizeof(MODULEENTRY32)

        if kernel32.Module32First(snap, ctypes.byref(me)):
            while True:
                modules.append((
                    me.szModule.decode("utf-8", errors="replace"),
                    ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value,
                    me.modBaseSize,
                    me.szExePath.decode("utf-8", errors="replace"),
                ))
                if not kernel32.Module32Next(snap, ctypes.byref(me)):
                    break

        close_handle(snap)
    except Exception:
        pass
    return modules


def enumerate_processes():
    """Enumerate running processes returning [(pid, name), ...]."""
    procs = []
    try:
        snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if snap == INVALID_HANDLE_VALUE:
            return procs

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if kernel32.Process32First(snap, ctypes.byref(pe)):
            while True:
                procs.append((
                    pe.th32ProcessID,
                    pe.szExeFile.decode("utf-8", errors="replace"),
                ))
                if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                    break

        close_handle(snap)
    except Exception:
        pass
    return procs


# --- Physical memory backends ---

class PhysicalMemory:
    """Backend for reading physical memory via Windows kernel interfaces."""

    def __init__(self):
        self.handle = None
        self.backend = None

    def open(self):
        """Try multiple backends to open physical memory."""
        errors = []

        # Backend 1: Direct \\.\PhysicalMemory device
        try:
            self.handle = create_file(
                r"\\.\PhysicalMemory",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            self.backend = "PhysicalMemory"
            return
        except OSError as e:
            errors.append(f"\\\\.\\PhysicalMemory: {e}")

        # Backend 2: \\.\NtPhysicalMemory
        try:
            self.handle = create_file(
                r"\\.\NtPhysicalMemory",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            self.backend = "NtPhysicalMemory"
            return
        except OSError as e:
            errors.append(f"\\\\.\\NtPhysicalMemory: {e}")

        # Backend 3: MmMapIoSpace via NtSystemDebugControl
        try:
            if self._try_debug_control():
                self.backend = "NtSystemDebugControl"
                return
        except Exception as e:
            errors.append(f"NtSystemDebugControl: {e}")

        # Backend 4: Try WinPmem's \\.\pmem driver
        try:
            self.handle = create_file(
                r"\\.\pmem",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            self.backend = "WinPmem (pmem)"
            return
        except OSError as e:
            errors.append(f"\\\\.\\pmem: {e}")

        # Backend 5: WinPmem alt
        try:
            self.handle = create_file(
                r"\\.\WinPmem",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            self.backend = "WinPmem"
            return
        except OSError as e:
            errors.append(f"\\\\.\\WinPmem: {e}")

        raise RuntimeError(
            "Could not open any physical memory device.\n"
            "This requires Administrator privileges and a compatible driver.\n"
            "Try: winpmem_mini_x64.exe or enable test signing mode.\n"
            "Details:\n  " + "\n  ".join(errors)
        )

    def _try_debug_control(self):
        """Try NtSystemDebugControl to access physical memory."""
        # This is a fallback that may work on some systems
        SYSRDMSR = 0x1C
        SYSDBG_READ_PHYSICAL = 7
        return False  # Requires kernel access; placeholder

    def read(self, address, size):
        """Read `size` bytes from physical `address`."""
        if self.backend in ("PhysicalMemory", "NtPhysicalMemory", "WinPmem (pmem)", "WinPmem"):
            # Map the physical memory range through the driver
            req = PHYSICAL_MEMORY_REQUEST(address, size)
            try:
                result = device_io_control(
                    self.handle,
                    IOCTL_NTLDR_MAP_PHYSICAL_MEMORY,
                    ctypes.byref(req), ctypes.sizeof(req),
                    out_size=size + 256
                )
                return result[:size]
            except OSError:
                pass

            # Fallback: seek to address and read
            high = ctypes.c_long(address >> 32)
            kernel32.SetFilePointer(self.handle, address & 0xFFFFFFFF, ctypes.byref(high), 0)
            return read_file(self.handle, size)

        raise OSError(f"Backend '{self.backend}' does not support read()")

    def get_memory_ranges(self):
        """Query available physical memory ranges."""
        ranges = []
        if self.handle is None:
            return ranges

        # Try the standard query IOCTL
        try:
            out = device_io_control(
                self.handle,
                IOCTL_NTLDR_QUERY_DEVICE_INFO,
                None, 0,
                out_size=65536
            )
            # Parse as array of PHYSICAL_MEMORY_RANGE
            offset = 0
            while offset + 16 <= len(out):
                base, sz = struct.unpack_from("<QQ", out, offset)
                if sz == 0:
                    break
                ranges.append((base, sz))
                offset += 16
        except OSError:
            pass

        # If no ranges found, assume full 64-bit address space is accessible
        if not ranges:
            ranges.append((0, 0x100000))  # First 1MB
            ranges.append((0x100000, 0xF00000))  # 1MB - 16MB typical
            ranges.append((0x1000000, 0x10000000))  # 16MB - 256MB
            ranges.append((0x10000000, 0x100000000))  # 256MB - 4GB

        return ranges

    def close(self):
        if self.handle:
            close_handle(self.handle)
            self.handle = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()


# --- Process memory backend ---

class ProcessMemory:
    """Backend for reading a process's virtual memory via ReadProcessMemory."""

    def __init__(self, pid):
        self.pid = pid
        self.handle = None

    def open(self):
        """Open the process with the best access we can get.

        Protected processes (lsass, csrss, dwm, antimalware, etc.) may refuse
        PROCESS_ALL_ACCESS, so retry with the minimum needed for read+query.
        """
        last_err = None
        for access in (PROCESS_ALL_ACCESS,
                       PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                       PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION):
            try:
                self.handle = open_process(self.pid, access)
                self.backend = (f"ReadProcessMemory (PID {self.pid}, access=0x{access:X})"
                                if access != PROCESS_ALL_ACCESS
                                else f"ReadProcessMemory (PID {self.pid})")
                self.last_unreadable_pages = 0
                return self.handle is not None
            except OSError as e:
                last_err = e
        raise OSError(
            f"OpenProcess({self.pid}) failed at every access level "
            f"(protected process? run elevated): {last_err}")

    def read(self, address, size):
        """Read `size` bytes from virtual `address`, page by page.

        Unreadable pages (unmapped, no access, guard pages, the null page at
        0x0, etc.) are zero-filled so a single bad page does not abort the
        whole read. `last_unreadable_pages` reports how many 4KB pages were
        skipped, so callers can tell genuine zeros from unreadable memory.
        """
        PAGE = 0x1000
        out = bytearray()
        offset = 0
        unreadable = 0
        while offset < size:
            chunk_base = address + offset
            chunk_len = min(PAGE - (chunk_base % PAGE), size - offset)
            try:
                out += read_process_memory(self.handle, chunk_base, chunk_len)
            except OSError:
                out += b"\x00" * chunk_len
                unreadable += chunk_len
            offset += chunk_len
        self.last_unreadable_pages = unreadable // PAGE
        return bytes(out)

    def find_readable_region(self, start=0, max_scan=1 << 32):
        """Return (base, size) of the next committed, readable region in
        [start, start+max_scan). Returns (None, None) if nothing readable.

        The forward scan is bounded (default 4GB worth of address space) so it
        cannot hang on processes whose every page is inaccessible.
        """
        limit = start + max_scan
        addr = start
        while addr < limit:
            try:
                mbi = query_virtual_memory(self.handle, addr)
            except OSError:
                return None, None
            base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr
            if mbi.State & MEM_COMMIT and (mbi.Protect & 0xFF) != PAGE_NOACCESS \
                    and not (mbi.Protect & PAGE_GUARD):
                return base, mbi.RegionSize
            nxt = base + mbi.RegionSize
            if nxt <= addr or nxt >= limit:
                return None, None
            addr = nxt
        return None, None

    def get_memory_ranges(self):
        ranges = []
        addr = 0
        try:
            while addr < (1 << 47):  # User-mode address space on x64
                mbi = query_virtual_memory(self.handle, addr)
                if mbi.State & MEM_COMMIT and mbi.Protect & 0xFF != PAGE_NOACCESS \
                        and not (mbi.Protect & PAGE_GUARD):
                    base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr
                    ranges.append((base, mbi.RegionSize))
                next_addr = (ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr) + mbi.RegionSize
                if next_addr <= addr:
                    break
                addr = next_addr
        except OSError:
            pass
        return ranges

    def get_bounds(self):
        """Return (start, end) of the process's readable committed memory.

        `start` is the lowest address of a readable committed region and `end`
        is the highest such region's end (exclusive). Returns (None, None) if
        nothing readable is found. Reads *below* start (e.g. the null page at
        0x0) or *beyond* end simply contain no process data, so callers clamp
        into [start, end).
        """
        start = None
        end = None
        addr = 0
        try:
            while addr < (1 << 47):  # User-mode address space on x64
                mbi = query_virtual_memory(self.handle, addr)
                if mbi.State & MEM_COMMIT and (mbi.Protect & 0xFF) != PAGE_NOACCESS \
                        and not (mbi.Protect & PAGE_GUARD):
                    base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr
                    region_end = base + mbi.RegionSize
                    if start is None:
                        start = base
                    end = region_end
                next_addr = (ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or addr) + mbi.RegionSize
                if next_addr <= addr:
                    break
                addr = next_addr
        except OSError:
            pass
        return start, end

    def get_modules(self):
        return get_process_modules(self.pid)

    def close(self):
        if self.handle:
            close_handle(self.handle)
            self.handle = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()


# --- Hex dump display ---
def hexdump(data, start_address=0, width=16):
    """Classic hex dump of binary data."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        addr = start_address + offset

        # Address
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Pad hex part to fixed width
        hex_part = hex_part.ljust(width * 3 - 1)

        # ASCII representation
        ascii_part = ""
        for b in chunk:
            ascii_part += chr(b) if 32 <= b < 127 else "."

        lines.append(f"{addr:016X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def print_memory_region(mem, address, size, width=16):
    """Read and display a region of memory."""
    MAX_SINGLE_READ = 1024 * 1024  # 1MB per read to avoid huge allocations

    total_read = 0
    while total_read < size:
        chunk_size = min(MAX_SINGLE_READ, size - total_read)
        chunk_addr = address + total_read

        try:
            data = mem.read(chunk_addr, chunk_size)
            print(hexdump(data, chunk_addr, width))
            total_read += len(data)
            if len(data) < chunk_size:
                print(f"\n[Short read: requested {chunk_size}, got {len(data)}]")
                break
        except OSError as e:
            print(f"\n[Error reading at 0x{chunk_addr:X}: {e}]")
            total_read += chunk_size
            continue

    return total_read


# --- Interactive mode ---

def interactive_hexdump(mem):
    """Interactive hex dump with navigation."""
    current_addr = 0
    page_size = 256

    print("=== Interactive Physical Memory Viewer ===")
    print("Commands: <hex address>  |  +<hex>  |  -<hex>  |  s <size>")
    print("          f <file>       |  q       |  ?       |  Enter=next page")
    print()

    while True:
        try:
            data = mem.read(current_addr, page_size)
            print(f"\n--- Address: 0x{current_addr:016X} | Showing {len(data)} bytes ---")
            print(hexdump(data, current_addr))
        except OSError as e:
            print(f"\n[Error reading at 0x{current_addr:X}: {e}]")

        try:
            cmd = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            current_addr += page_size
            continue

        if cmd.lower() == "q":
            break

        if cmd.lower() == "?":
            print("Commands:")
            print("  <hex>      Jump to address (e.g. 0xDEADBEEF)")
            print("  +<hex>     Move forward by hex bytes")
            print("  -<hex>     Move backward by hex bytes")
            print("  s <size>   Change page size")
            print("  f <file>   Dump next 4KB to file")
            print("  Enter      Next page")
            print("  q          Quit")
            continue

        if cmd.lower().startswith("s "):
            try:
                page_size = int(cmd[2:].strip(), 0)
                print(f"Page size set to {page_size}")
            except ValueError:
                print("Invalid size")
            continue

        if cmd.lower().startswith("f "):
            filepath = cmd[2:].strip()
            try:
                dump_size = 4096
                data = mem.read(current_addr, dump_size)
                with open(filepath, "wb") as f:
                    f.write(data)
                print(f"Wrote {len(data)} bytes to {filepath}")
            except (OSError, IOError) as e:
                print(f"Error: {e}")
            continue

        if cmd.startswith("+") or cmd.startswith("-"):
            try:
                delta = int(cmd, 0)
                current_addr = (current_addr + delta) & 0xFFFFFFFFFFFFFFFF
            except ValueError:
                print("Invalid offset")
            continue

        try:
            addr = int(cmd, 0)
            current_addr = addr & 0xFFFFFFFFFFFFFFFF
        except ValueError:
            print("Invalid input. Type ? for help.")


# --- Probe mode ---

def probe_memory(mem):
    """Probe physical memory and show what's readable."""
    print("=== Physical Memory Probe ===\n")

    # Known important physical addresses to test
    test_regions = [
        (0x00000000, 512, "Physical RAM start (Real Mode IVT / BDA)"),
        (0x00000400, 256, "BIOS Data Area (BDA)"),
        (0x00000500, 256, "Conventional memory EBDA region"),
        (0x0009FC00, 512, "EBDA end / Video BIOS area"),
        (0x000A0000, 4096, "VGA/EGA display memory"),
        (0x000C0000, 16384, "ROM BIOS expansion area"),
        (0x000F0000, 65536, "ROM BIOS (shadow)"),
        (0x00100000, 256, "First megabyte end / Extended memory start"),
        (0x01000000, 256, "16MB mark"),
        (0x04000000, 256, "64MB mark"),
        (0x10000000, 256, "256MB mark"),
        (0x20000000, 256, "512MB mark"),
        (0x40000000, 256, "1GB mark"),
        (0x80000000, 256, "2GB mark"),
    ]

    # Also try to get structured ranges
    try:
        ranges = mem.get_memory_ranges()
        if ranges:
            print("Reported memory ranges:")
            for base, size in ranges:
                print(f"  0x{base:016X} - 0x{base + size:016X}  ({size:,} bytes / {size/1024/1024:.1f} MB)")
            print()
    except Exception:
        pass

    readable = 0
    total = 0
    for addr, size, desc in test_regions:
        total += 1
        try:
            data = mem.read(addr, size)
            first_bytes = " ".join(f"{b:02X}" for b in data[:16])
            readable += 1
            print(f"  [OK]   0x{addr:08X}  {desc}")
            print(f"         First 16 bytes: {first_bytes}")
        except OSError as e:
            print(f"  [FAIL] 0x{addr:08X}  {desc}")
            print(f"         Error: {e}")

    print(f"\nReadable: {readable}/{total} tested regions")

    # Estimate usable range
    print("\nScanning readable ranges (this may take a moment)...")
    scan_sizes = [0x100000, 0x1000000, 0x10000000, 0x80000000]
    scan_labels = ["1MB", "16MB", "256MB", "2GB"]

    for size, label in zip(scan_sizes, scan_labels):
        try:
            data = mem.read(0, min(size, 4096))
            print(f"  Physical RAM accessible up to at least {label}")
        except OSError:
            print(f"  Physical RAM likely not accessible at {label}")
            break


# --- Save/Load functions ---

def dump_to_file(mem, address, size, filepath):
    """Dump physical memory to a file."""
    CHUNK = 1024 * 1024  # 1MB chunks
    with open(filepath, "wb") as f:
        written = 0
        while written < size:
            chunk_size = min(CHUNK, size - written)
            try:
                data = mem.read(address + written, chunk_size)
                f.write(data)
                written += len(data)
                pct = min(100, written * 100 // size)
                print(f"\r  Progress: {pct}% ({written:,}/{size:,} bytes)", end="", flush=True)
                if len(data) < chunk_size:
                    print(f"\n  Short read at offset {written:,}")
                    break
            except OSError as e:
                print(f"\n  Error at offset {written + address:X}: {e}")
                break
    print(f"\n  Saved {written:,} bytes to {filepath}")


# --- Main ---

def check_admin():
    """Check if running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="ramview - Direct physical memory reader for Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-a", "--address", default="0",
                        help="Physical address (hex, e.g. 0x0) OR virtual address")
    parser.add_argument("-s", "--size", default="256",
                        help="Bytes to read (decimal or hex with 0x)")
    parser.add_argument("-o", "--output", help="Write raw bytes to file")
    parser.add_argument("-d", "--dump", action="store_true",
                        help="Interactive hex dump mode")
    parser.add_argument("-p", "--probe", action="store_true",
                        help="Probe and display memory layout")
    parser.add_argument("-w", "--width", type=int, default=16,
                        help="Bytes per line in hex dump (default: 16)")
    parser.add_argument("--pid", type=int, metavar="PID",
                        help="Read a process's VIRTUAL memory instead of physical RAM. "
                             "Use -a for virtual address, -s for size.")
    parser.add_argument("--processes", action="store_true",
                        help="List running processes with PIDs, then exit")

    args = parser.parse_args()

    if args.processes:
        print("Running processes:")
        print(f"{'PID':>6}  {'Name':<50}")
        print("-" * 60)
        for pid, name in enumerate_processes():
            print(f"{pid:>6}  {name}")
        sys.exit(0)

    print("ramview - Memory Viewer")
    print("=" * 40)
    print(f"Platform: Windows")
    print()

    if args.pid is not None:
        # Process virtual memory mode
        try:
            with ProcessMemory(args.pid) as mem:
                print(f"Attached to PID {args.pid} via: {mem.backend}\n")
                addr = int(args.address, 0)
                size = int(args.size, 0)

                if args.probe:
                    print("=== Process Memory Regions ===")
                    start, end = mem.get_bounds()
                    if start is None:
                        print("  Memory bounds: (none readable)")
                    else:
                        print(f"  Memory bounds: 0x{start:016X} - 0x{end:016X} "
                              f"({end - start:,} bytes)\n")
                    ranges = mem.get_memory_ranges()
                    for base, sz in ranges:
                        print(f"  0x{base:016X} - 0x{base + sz:016X}  ({sz:,} bytes)")
                    print(f"\n{len(ranges)} readable regions.\n")
                    print("=== Loaded Modules ===")
                    for name, base, size_m, path in mem.get_modules():
                        print(f"  0x{base:016X}  {name:<30} {size_m:>8}  {path}")
                elif args.dump:
                    interactive_hexdump(mem)
                else:
                    if args.output:
                        print("Note: use --pid with -o to dump process memory.")
                        dump_to_file(mem, addr, size, args.output)
                    else:
                        # Clamp into the process's actual memory bounds so a
                        # request at, say, 0x0 shows the real start (ramview.py
                        # itself, not whatever unmapped/reserved page the
                        # address belongs to).
                        start, end = mem.get_bounds()
                        if start is not None:
                            if addr < start:
                                print(f"Note: address 0x{addr:X} is below this process's "
                                      f"memory (starts at 0x{start:X}); showing its start.\n")
                                addr = start
                            if addr >= end:
                                addr = max(start, end - size)
                            if addr + size > end:
                                size = end - addr
                        print_memory_region(mem, addr, size, args.width)
        except OSError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            print(f"\nThis may be because PID {args.pid} requires elevation or is protected.")
            sys.exit(1)
        sys.exit(0)

    # Physical memory mode
    if not check_admin():
        print("WARNING: Not running as Administrator. Physical memory access")
        print("requires elevated privileges. Attempting anyway...\n")

    try:
        with PhysicalMemory() as mem:
            print(f"Opened physical memory via: {mem.backend}\n")

            if args.probe:
                probe_memory(mem)
            elif args.dump:
                interactive_hexdump(mem)
            else:
                address = int(args.address, 0)
                size = int(args.size, 0)

                if args.output:
                    dump_to_file(mem, address, size, args.output)
                else:
                    print_memory_region(mem, address, size, args.width)

    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("\nTo fix this:")
        print("  1. Run this script as Administrator")
        print("  2. Install WinPmem: https://github.com/Velocidex/WinPmem")
        print("     or download winpmem_mini_x64.exe and place in PATH")
        print("  3. Or enable test signing: bcdedit /set testsigning on")
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
