"""Read-only Windows PE triage. Does not execute or patch the target."""
from pathlib import Path
import argparse
import collections
import hashlib
import json
import math
import re

import pefile

MARKERS = re.compile(r"adb|fastboot|cp210|silab|uart|baud|qserialport|serialport|open.?adb|unlock|websocket|winusb|edl|qualcomm|api\.lixiang", re.I)
ASCII = re.compile(rb"[\x20-\x7e]{6,180}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,180}")
MAX_FILES = 2200
MAX_PE = 60
MAX_SCAN = 24 * 1024 * 1024

def filehash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def inspect(path):
    result = {"sha256": filehash(path)}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        result["machine"] = hex(pe.FILE_HEADER.Machine)
        result["imports"] = [
            item.dll.decode("ascii", "replace")
            for item in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        ][:80]
        result["sections"] = []
        for sec in pe.sections[:32]:
            data = sec.get_data()[:8 * 1024 * 1024]
            if data:
                counts = collections.Counter(data)
                entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())
            else:
                entropy = 0.0
            result["sections"].append({
                "name": sec.Name.decode("ascii", "replace").strip("\0"),
                "entropy": round(entropy, 3),
                "size": int(sec.SizeOfRawData),
            })
        pe.close()
    except Exception as exc:
        result["pe_error"] = str(exc)[:180]
    with path.open("rb") as stream:
        raw = stream.read(MAX_SCAN)
    strings = []
    for regex, encoding in ((ASCII, "ascii"), (UTF16, "utf-16le")):
        for match in regex.finditer(raw):
            candidate = match.group().decode(encoding, "replace")
            if MARKERS.search(candidate):
                candidate = re.sub(r"https?://\S+", "[URL REDACTED]", candidate)
                candidate = re.sub(r"(?:password|secret|token|api_key)\s*[=:]\s*\S+", "[CREDENTIAL REDACTED]", candidate, flags=re.I)
                if candidate not in strings:
                    strings.append(candidate[:180])
            if len(strings) >= 50:
                break
        if len(strings) >= 50:
            break
    result["indicator_strings"] = strings
    return result

def main(root, out):
    out.mkdir(parents=True, exist_ok=True)
    files = [p for p in root.rglob("*") if p.is_file() and not p.is_symlink()][:MAX_FILES]
    files.sort(key=lambda p: (
        0 if p.name.lower() == "litools_v2.0.exe" else 1,
        0 if re.search(r"litools|lixiang|main|bridge|serial|adb", p.name, re.I) else 1,
        0 if p.suffix.lower() in (".exe", ".dll") else 1,
        p.name
    ))
    results = []
    for f in files:
        try:
            size = f.stat().st_size
            with f.open("rb") as stream:
                is_pe = stream.read(2) == b"MZ"
        except OSError:
            continue
        rec = {"path": f.relative_to(root).as_posix(), "size": size, "is_pe": is_pe}
        if is_pe and sum("pe" in x for x in results) < MAX_PE:
            try:
                rec["pe"] = inspect(f)
            except Exception as exc:
                rec["analysis_error"] = str(exc)[:180]
        results.append(rec)
    data = {"method": "static_only", "file_count": len(results), "results": results}
    (out / "static_facts.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# LIXIANGTOOLS static inspection", "",
             "Read-only PE/header and embedded-string triage. **No application execution or vehicle access**.",
             "", f"Scanned {len(results)} files, up to {MAX_PE} PE files.", "",
             "## PE files", ""]
    for r in results:
        if "pe" not in r:
            continue
        p = r["pe"]
        lines.extend([
            f"### {r['path']}", "",
            f"- SHA-256: \`{p['sha256']}\`",
            f"- CPU machine: {p.get('machine', 'unknown')}",
            "- Imported DLLs: " + ", ".join(p.get("imports", [])),
            "- Sections: " + ", ".join(x["name"] + " (entropy " + str(x["entropy"]) + ")" for x in p.get("sections", [])[:12]),
            "- Notable embedded strings (not proof of behavior):",
        ])
        lines += ["  - " + s.replace("\n", " ").replace("\r", " ") for s in p.get("indicator_strings", [])[:30]]
        lines.append("")
    lines += [
        "## Not determined",
        "- Whether OTA 8.7 can be unlocked",
        "- Exact UART pinout, baud, handshake or message structure",
        "- Whether the actual OPEN ADB payload comes from the server",
        "- Runtime behavior behind any packed/VMProtect code",
    ]
    (out / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", default="reports", type=Path)
    a = parser.parse_args()
    main(a.root, a.output)
