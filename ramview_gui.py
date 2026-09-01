#!/usr/bin/env python3
"""ramview_gui - GUI frontend for ramview (Windows memory viewer)."""

import ctypes
import ctypes.wintypes as wintypes
import sys
import os
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import ramview

MONO_FONT = ("Consolas", 10)


class RamViewGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ramview - Windows Memory Viewer")
        self.root.geometry("1100x700")
        self.root.minsize(760, 480)

        self.mem = None          # active backend (PhysicalMemory or ProcessMemory)
        self.current_addr = 0    # last address shown
        self.display_size = 512  # bytes shown per page by default
        self.result_q = queue.Queue()

        self._build_menu()
        self._build_toolbar()
        self._build_display()
        self._build_statusbar()

        self.refresh_processes()
        self.root.after(100, self._poll_results)

    # ---------------------------------------------------------------- build

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save raw bytes...", command=self._on_save_dump, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Probe / list regions", command=self.on_probe, accelerator="F5")
        view_menu.add_command(label="Clear display", command=self._clear_display)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self._show_help)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(6, 6, 6, 2))
        bar.pack(side=tk.TOP, fill=tk.X)

        # Backend / mode
        self.mode_var = tk.StringVar(value="physical")
        row1 = ttk.Frame(bar)
        row1.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row1, text="Target:").pack(side=tk.LEFT)
        ttk.Radiobutton(row1, text="Physical RAM", value="physical",
                        variable=self.mode_var, command=self._mode_changed).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Radiobutton(row1, text="Process", value="process",
                        variable=self.mode_var, command=self._mode_changed).pack(side=tk.LEFT, padx=(4, 0))

        self.pid_var = tk.StringVar()
        self.pid_combo = ttk.Combobox(row1, textvariable=self.pid_var, width=34, state="readonly")
        self.pid_combo.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_refresh_pids = ttk.Button(row1, text="Refresh", command=self.refresh_processes)
        self.btn_refresh_pids.pack(side=tk.LEFT, padx=(4, 0))
        self.btn_modules = ttk.Button(row1, text="Modules", command=self._show_modules)
        self.btn_modules.pack(side=tk.LEFT, padx=(4, 0))

        # Address / size / actions
        row2 = ttk.Frame(bar)
        row2.pack(fill=tk.X)
        ttk.Label(row2, text="Address (hex):").pack(side=tk.LEFT)
        self.addr_var = tk.StringVar(value="0x0")
        self.entry_addr = ttk.Entry(row2, textvariable=self.addr_var, width=20)
        self.entry_addr.pack(side=tk.LEFT, padx=(4, 0))

        ttk.Label(row2, text="Bytes:").pack(side=tk.LEFT, padx=(8, 0))
        self.size_var = tk.StringVar(value="512")
        self.entry_size = ttk.Entry(row2, textvariable=self.size_var, width=10)
        self.entry_size.pack(side=tk.LEFT, padx=(4, 0))

        self.btn_read = ttk.Button(row2, text="Read", command=self.on_read)
        self.btn_read.pack(side=tk.LEFT, padx=(10, 0))
        self.btn_probe = ttk.Button(row2, text="Probe", command=self.on_probe)
        self.btn_probe.pack(side=tk.LEFT, padx=(4, 0))
        self.btn_save = ttk.Button(row2, text="Save...", command=self._on_save_dump)
        self.btn_save.pack(side=tk.LEFT, padx=(4, 0))
        self.btn_pageup = ttk.Button(row2, text="<- Prev", command=self._on_prev_page)
        self.btn_pageup.pack(side=tk.LEFT, padx=(12, 0))
        self.btn_pagedn = ttk.Button(row2, text="Next ->", command=self._on_next_page)
        self.btn_pagedn.pack(side=tk.LEFT, padx=(4, 0))

        self.entry_addr.bind("<Return>", lambda e: self.on_read())
        self.entry_size.bind("<Return>", lambda e: self.on_read())

        self.root.bind("<Control-s>", lambda e: self._on_save_dump())
        self.root.bind("<F5>", lambda e: self.on_probe())
        self.root.bind("<F3>", lambda e: self.on_read())

    def _build_display(self):
        frame = ttk.Frame(self.root, padding=(6, 2, 6, 2))
        frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.txt = scrolledtext.ScrolledText(
            frame, wrap=tk.NONE, font=MONO_FONT,
            state=tk.DISABLED, background="#0d1117", foreground="#e6edf3",
            insertbackground="#e6edf3", selectbackground="#1f6feb"
        )
        self.txt.pack(fill=tk.BOTH, expand=True)

        vsb = self.txt.vbar
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.txt.xview)
        self.txt.configure(xscrollcommand=hsb.set)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready")
        bar = ttk.Frame(self.root, relief=tk.SUNKEN)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(bar, textvariable=self.status_var, anchor=tk.W,
                  padding=(6, 2)).pack(side=tk.LEFT, fill=tk.X, expand=True)

    # -------------------------------------------------------------- helpers

    def _set_status(self, text):
        self.status_var.set(text)
        self.root.update_idletasks()

    def _append_text(self, text):
        self.txt.configure(state=tk.NORMAL)
        self.txt.insert(tk.END, text)
        self.txt.configure(state=tk.DISABLED)
        self.txt.see(tk.END)

    def _set_text(self, text):
        self.txt.configure(state=tk.NORMAL)
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, text)
        self.txt.configure(state=tk.DISABLED)
        self.txt.see("1.0")

    def _clear_display(self):
        self._set_text("")

    # ---------------------------------------------------------------- modes

    def _open_backend(self):
        """Open (or reopen) the currently selected backend."""
        try:
            if self.mode_var.get() == "process":
                sel = self.pid_combo.get()
                if not sel:
                    messagebox.showwarning("ramview", "Select a process from the list first.")
                    return False
                pid = int(sel.split()[0])
                self.mem = ramview.ProcessMemory(int(pid))
            else:
                self.mem = ramview.PhysicalMemory()
            self.mem.open()
            return True
        except Exception as e:
            messagebox.showerror("ramview", f"Could not open memory:\n{e}")
            self.mem = None
            return False

    def _mode_changed(self):
        self._clear_display()
        self.mem = None
        if self.mode_var.get() == "process":
            self.pid_combo.configure(state="readonly")
            self.btn_modules.configure(state="normal")
        else:
            self.pid_combo.configure(state="disabled")
            self.btn_modules.configure(state="disabled")
        self._set_status("Mode set to " + ("Process memory" if self.mode_var.get() == "process"
                                           else "Physical RAM"))

    def _parse_addr(self):
        try:
            return int(self.addr_var.get().strip(), 0)
        except ValueError:
            raise ValueError(f"Bad address: {self.addr_var.get()!r}")

    def _parse_size(self):
        try:
            return int(self.size_var.get().strip(), 0)
        except ValueError:
            raise ValueError(f"Bad size: {self.size_var.get()!r}")

    # ------------------------------------------------------------- actions

    def refresh_processes(self):
        self._set_status("Enumerating processes...")
        procs = ramview.enumerate_processes()
        self._process_list = procs
        self.pid_combo.configure(values=[f"{pid}  {name}" for pid, name in procs])
        self._set_status(f"Ready ({len(procs)} processes enumerated)")

    def _find_pid(self):
        sel = self.pid_combo.get()
        if not sel:
            return None
        return int(sel.split()[0])

    def on_read(self, _event=None):
        if self.mem is None and not self._open_backend():
            return
        try:
            addr = self._parse_addr()
            size = self._parse_size()
        except ValueError as e:
            messagebox.showerror("ramview", str(e))
            return

        if size <= 0:
            messagebox.showerror("ramview", "Size must be positive.")
            return
        if size > 4 * 1024 * 1024:
            if not messagebox.askyesno("ramview",
                                       f"{size:,} bytes is a lot to display. Continue?"):
                return

        self.current_addr = addr
        self.display_size = size
        self._set_status(f"Reading 0x{addr:X} ...")
        threading.Thread(target=self._read_job, args=(addr, size), daemon=True).start()

    def _read_job(self, addr, size):
        mem = self.mem
        data = b""
        note = ""
        error = None
        try:
            if isinstance(mem, ramview.ProcessMemory):
                # Find where this process's memory actually starts and ends, then
                # clamp the request into that range so we never read the null
                # page or unmapped space and show the correct data.
                start, end = mem.get_bounds()
                if start is None or end is None:
                    note = (f"Could not determine this process's memory bounds "
                            f"(PID {self._find_pid()}).\n")
                    error = "no readable memory found for this process"
                else:
                    if addr < start:
                        note = (f"Address 0x{addr:X} is below this process's memory "
                                f"(starts at 0x{start:X}); showing the start instead.\n")
                        addr = start
                    if addr >= end:
                        note = (f"Address 0x{addr:X} is past this process's memory "
                                f"(ends at 0x{end:X}); showing the end instead.\n")
                        addr = max(start, end - size)
                    if addr + size > end:
                        size = end - addr
                    self.addr_var.set(hex(start if start == addr else addr))
                    self.current_addr = addr
                    self.display_size = size

            data = mem.read(addr, size)
            if isinstance(mem, ramview.ProcessMemory):
                unreadable = getattr(mem, "last_unreadable_pages", 0)
                if unreadable * 0x1000 >= size:
                    # Entire range unreadable -> auto-jump to next readable region
                    base, rsize = mem.find_readable_region(addr)
                    if base is not None:
                        view_size = min(size, rsize)
                        data = mem.read(base, view_size)
                        note = (f"Address 0x{addr:X} was not readable; showing next "
                                f"readable region at 0x{base:X}.\n")
                        self.addr_var.set(hex(base))
                        self.current_addr = base
                        self.display_size = view_size
                    else:
                        note = (f"No readable memory found for this process at or "
                                f"after 0x{addr:X}.\n")
                elif unreadable:
                    note = (f"Note: {unreadable} page(s) were unreadable and are "
                            f"shown as zeros.\n")
        except Exception as e:
            error = str(e)
        self.result_q.put(("hexdump", addr, size, data, error, note))

    def on_probe(self, _event=None):
        if self.mem is None and not self._open_backend():
            return
        self._set_status("Probing...")
        threading.Thread(target=self._probe_job, daemon=True).start()

    def _probe_job(self):
        lines = []
        error = None
        try:
            if isinstance(self.mem, ramview.PhysicalMemory):
                lines.append("=== Physical Memory Probe ===\n")
                try:
                    ranges = self.mem.get_memory_ranges()
                    lines.append("\nReported memory ranges:\n")
                    for base, sz in ranges:
                        lines.append(f"  0x{base:016X} - 0x{base+sz:016X}  "
                                     f"({sz:,} bytes / {sz/1024/1024:.1f} MB)\n")
                except Exception:
                    pass

                test_regions = [
                    (0x00000000, 512, "Physical RAM start (IVT / BDA)"),
                    (0x00000400, 256, "BIOS Data Area (BDA)"),
                    (0x0009FC00, 512, "EBDA end / Video BIOS area"),
                    (0x000A0000, 4096, "VGA/EGA display memory"),
                    (0x000C0000, 16384, "ROM BIOS expansion area"),
                    (0x000F0000, 65536, "ROM BIOS (shadow)"),
                    (0x00100000, 256, "Start of extended memory"),
                    (0x10000000, 256, "256MB mark"),
                    (0x40000000, 256, "1GB mark"),
                    (0x80000000, 256, "2GB mark"),
                ]
                lines.append("\nReadability test:\n")
                ok = 0
                for addr, sz, desc in test_regions:
                    try:
                        data = self.mem.read(addr, sz)
                        first = " ".join(f"{b:02X}" for b in data[:16])
                        ok += 1
                        lines.append(f"  [OK]   0x{addr:08X}  {desc}\n")
                        lines.append(f"         {first}\n")
                    except Exception as e:
                        lines.append(f"  [FAIL] 0x{addr:08X}  {desc}  ({e})\n")
                lines.append(f"\nReadable: {ok}/{len(test_regions)}\n")
            else:
                lines.append(f"=== Process Memory (PID {self._find_pid()}) ===\n")
                try:
                    start, end = self.mem.get_bounds()
                    if start is None:
                        lines.append("\n  Memory bounds: (none readable)\n")
                    else:
                        lines.append(f"\nMemory bounds: 0x{start:016X} - 0x{end:016X} "
                                     f"({end - start:,} bytes)\n")
                except Exception as e:
                    lines.append(f"\n  (could not determine bounds: {e})\n")
                lines.append("\nReadable regions:\n")
                try:
                    ranges = self.mem.get_memory_ranges()
                    for base, sz in ranges:
                        lines.append(f"  0x{base:016X} - 0x{base+sz:016X}  ({sz:,} bytes)\n")
                    lines.append(f"\n{len(ranges)} readable regions.\n")
                except Exception as e:
                    lines.append(f"  (could not enumerate: {e})\n")
        except Exception as e:
            error = str(e)
        self.result_q.put(("probe", "".join(lines), error))

    def _show_modules(self):
        if self.mode_var.get() != "process":
            return
        pid = self._find_pid()
        if pid is None:
            messagebox.showwarning("ramview", "Select a process first.")
            return
        self._set_status("Reading modules...")
        threading.Thread(target=self._modules_job, args=(pid,), daemon=True).start()

    def _modules_job(self, pid):
        lines = [f"=== Loaded Modules (PID {pid}) ===\n\n"]
        error = None
        try:
            mods = ramview.get_process_modules(pid)
            if not mods:
                lines.append("  (none enumerated - may require elevation for this process)\n")
            for name, base, sz, path in mods:
                lines.append(f"  0x{base:016X}  {name:<32} {sz:>9,}  {path}\n")
            lines.append(f"\n{len(mods)} modules.\n")
        except Exception as e:
            error = str(e)
        self.result_q.put(("modules", "".join(lines), error))

    def _on_save_dump(self):
        if self.mem is None and not self._open_backend():
            return
        try:
            addr = self._parse_addr()
            size = self._parse_size()
        except ValueError as e:
            messagebox.showerror("ramview", str(e))
            return
        fn = filedialog.asksaveasfilename(
            title="Save raw memory",
            defaultextension=".bin",
            initialfile=f"mem_{addr:016X}_{size}.bin",
            filetypes=[
                ("Raw binary (*.bin)", "*.bin"),
                ("Raw memory data (*.raw)", "*.raw"),
                ("All files (*.*)", "*.*"),
            ])
        if not fn:
            return
        self._set_status(f"Saving {size:,} bytes to {os.path.basename(fn)} ...")
        threading.Thread(target=self._save_job, args=(addr, size, fn), daemon=True).start()

    def _save_job(self, addr, size, fn):
        error = None
        try:
            from io import BytesIO
            CHUNK = 1024 * 1024
            written = 0
            with open(fn, "wb") as f:
                buf = BytesIO()
                while written < size:
                    chunk_size = min(CHUNK, size - written)
                    try:
                        data = self.mem.read(addr + written, chunk_size)
                    except Exception:
                        # skip unreadable gaps in physical memory
                        buf.write(b"\x00" * chunk_size)
                        written += chunk_size
                        continue
                    f.write(data)
                    written += len(data)
                    if len(data) == 0:
                        break
        except Exception as e:
            error = str(e)
        self.result_q.put(("saved", written, fn, error))

    def _on_prev_page(self):
        if self.mem is not None:
            self.addr_var.set(hex(self.current_addr - self.display_size))
            self.on_read()

    def _on_next_page(self):
        if self.mem is not None:
            self.addr_var.set(hex(self.current_addr + self.display_size))
            self.on_read()

    # ----------------------------------------------------------- results

    def _poll_results(self):
        try:
            while True:
                msg = self.result_q.get_nowait()
                kind = msg[0]

                if kind == "hexdump":
                    _, addr, size, data, error, note = msg
                    if error:
                        self._set_text(f"Error reading 0x{addr:X}: {error}")
                        self._set_status("Read failed")
                    else:
                        lines = ramview.hexdump(data, addr)
                        truncated = ""
                        if size > len(data):
                            truncated = (f"\n[Note: only {len(data)} of {size} bytes returned "
                                         f"(unreadable region) - showing available]\n")
                        self._set_text((note or "") + lines + truncated)
                        self._set_status(f"0x{addr:X}: {len(data):,} bytes displayed "
                                         f"(requested {size:,})")

                elif kind == "probe":
                    _, text, error = msg
                    self._set_text(text + (f"\nProbe error: {error}\n" if error else ""))
                    self._set_status("Probe complete")

                elif kind == "modules":
                    _, text, error = msg
                    self._set_text(text + (f"\nModule error: {error}\n" if error else ""))
                    self._set_status("Modules loaded")

                elif kind == "saved":
                    _, written, fn, error = msg
                    if error:
                        self._set_status(f"Save error: {error}")
                        messagebox.showerror("ramview", f"Save failed:\n{error}")
                    else:
                        self._set_status(f"Saved {written:,} bytes to {fn}")
                        messagebox.showinfo("ramview", f"Saved {written:,} bytes to:\n{fn}")

        except queue.Empty:
            pass
        self.root.after(100, self._poll_results)

    # --------------------------------------------------------------- help

    def _show_help(self):
        msgbox = ("ramview GUI\n\n"
                  "Target\n"
                  "  Physical RAM - read raw physical memory (needs WinPmem driver + admin).\n"
                  "  Process - read a running process's virtual memory.\n\n"
                  "Controls\n"
                  "  Address: physical or virtual address (0x prefix = hex).\n"
                  "  Bytes: amount to read/display.\n"
                  "  Read / F3: read at address.\n"
                  "  Probe / F5: list regions (physical) or readable ranges (process).\n"
                  "  Save... / Ctrl+S: dump raw bytes to a file.\n"
                  "  <- Prev / Next ->: move up/down a page.\n"
                  "  Modules: list DLLs loaded in the selected process.\n\n"
                  "Physical RAM requires the signed WinPmem driver running "
                  "(see README).")
        messagebox.showinfo("ramview - Help", msgbox)

    def _show_about(self):
        messagebox.showinfo("ramview",
                            "ramview - Windows Memory Viewer\n\n"
                            "Reads raw bytes from physical RAM or a process's "
                            "virtual memory.\n\nBackends:\n"
                            + ", ".join(["PhysicalMemory", "NtPhysicalMemory",
                                         "WinPmem", "ReadProcessMemory"]))


def main():
    if sys.platform != "win32":
        print("ramview GUI is Windows-only.")
        sys.exit(1)
    root = tk.Tk()
    RamViewGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()