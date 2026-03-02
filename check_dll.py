import pefile
import os
import sys
import re
import csv

# DLLs that are "safe" system DLLs unlikely to be hijackable
SYSTEM_DLLS = {d.lower() for d in [
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "msvcrt.dll", "shell32.dll", "ole32.dll", "comctl32.dll",
    # add more known-safe ones as needed
]}

WRITABLE_ROOTS = [
    os.environ.get("APPDATA", ""),
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
]

def is_writable(path):
    try:
        return os.access(path, os.W_OK)
    except:
        return False

def check_exe(exe_path):
    results = []
    seen = set()
    exe_dir = os.path.dirname(os.path.abspath(exe_path))
    try:
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return results
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace").lower()
            if dll_name in SYSTEM_DLLS:
                continue
            # Check if this DLL exists in the exe's own directory (writable hijack)
            candidate = os.path.join(exe_dir, dll_name)
            if not os.path.exists(candidate) and is_writable(exe_dir):
                finding = (dll_name, exe_dir, "EXE directory is writable, DLL missing")
                if finding not in seen:
                    seen.add(finding)
                    results.append(finding)
            # Check APPDATA, TEMP etc.
            for root in WRITABLE_ROOTS:
                if not root:
                    continue
                candidate = os.path.join(root, dll_name)
                if not os.path.exists(candidate):
                    finding = (dll_name, root, "Writable location, DLL missing")
                    if finding not in seen:
                        seen.add(finding)
                        results.append(finding)
        pe.close()
    except Exception as e:
        results.append(("ERROR", str(e), ""))
    return results

def extract_dlls_from_msi(msi_path):
    with open(msi_path, "rb") as handle:
        data = handle.read()
    matches = re.findall(rb"([A-Za-z0-9_\-.]{2,128}\.dll)", data, flags=re.IGNORECASE)
    return sorted({match.decode(errors="replace").lower() for match in matches})

def check_msi(msi_path):
    results = []
    seen = set()
    msi_dir = os.path.dirname(os.path.abspath(msi_path))
    try:
        dll_names = extract_dlls_from_msi(msi_path)
        for dll_name in dll_names:
            if dll_name in SYSTEM_DLLS:
                continue
            candidate = os.path.join(msi_dir, dll_name)
            if not os.path.exists(candidate) and is_writable(msi_dir):
                finding = (dll_name, msi_dir, "MSI directory is writable, DLL missing")
                if finding not in seen:
                    seen.add(finding)
                    results.append(finding)
            for root in WRITABLE_ROOTS:
                if not root:
                    continue
                candidate = os.path.join(root, dll_name)
                if not os.path.exists(candidate):
                    finding = (dll_name, root, "Writable location, DLL missing")
                    if finding not in seen:
                        seen.add(finding)
                        results.append(finding)
    except Exception as e:
        results.append(("ERROR", str(e), ""))
    return results

def check_file(target_path):
    extension = os.path.splitext(target_path)[1].lower()
    if extension == ".exe":
        return check_exe(target_path)
    if extension == ".msi":
        return check_msi(target_path)
    raise ValueError("Unsupported file type. Use a single .exe or .msi file.")

def write_csv_log(target_path, hits):
    target_filename = os.path.basename(target_path)
    log_path = f"{target_filename}.log"
    with open(log_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if hits:
            for dll, location, reason in hits:
                writer.writerow([target_filename, dll, location, reason])
        else:
            writer.writerow([target_filename, "INFO", "", "No suspicious missing DLL locations found."])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_dll.py <target.exe|target.msi>")
        sys.exit(1)

    target_file = os.path.abspath(sys.argv[1])
    if not os.path.isfile(target_file):
        print(f"Error: Not a file: {target_file}")
        sys.exit(1)

    try:
        hits = check_file(target_file)
    except ValueError as err:
        print(f"Error: {err}")
        sys.exit(1)

    print(f"\n[*] Scan target: {target_file}")
    if hits:
        for dll, location, reason in hits:
            print(f"    DLL: {dll}  |  Location: {location}  |  {reason}")
    else:
        print("    No suspicious missing DLL locations found.")

    write_csv_log(target_file, hits)
