"""Read-only focused triage of installed LIXIANGTOOLS.exe.
Does not execute target or upload proprietary binaries.
"""
import argparse
import json
import re
from pathlib import Path

KEYWORDS = {
    "unlock": r"open.?adb|openadb|unlock.?adb|enable.?adb|adb.?enable|adb.?unlock|adb.?lock",
    "serial": r"qserialport|qtserialport|serialport|uart|baudrate|baud.?rate|cp210|silabser|tty|comport|portname",
    "android": r"adbclient|adb_server|android_adb|adb_exe|fastboot|scrcpy|qcom|qualcomm",
    "remote": r"license|activation|authorize|auth|token|server_url|base_url|api_url|api_host|websocket|wss:|https:|http:|download|session|request|payload",
    "fastboot": r"fastboot|laconfig|flash|reboot|bootloader|unlock\.fastboot",
    "ui_bridge": r"Bridge\.|OpenAdbRunner|qwebchannel|openadb_runner|startOpenAdb",
    "compiler": r"nuitka|pyinstaller|cx_freeze|pyoxidizer|py2exe|py_?init|python313",
    "vehicle": r"lixiang|vin|OTA|model|vehicle|firmware",
    "crypto": r"signature|rsa|ecdsa|ed25519|aes|encrypt|decrypt|hmac",
}
MAX_PER_GROUP = 100
MAX_BYTES = 24 * 1024 * 1024

def scrub(text: str) -> str:
    text = text[:220].replace("\r", " ").replace("\n", " ")
    text = re.sub(r"https?://[^\s)\"'<>]+", "[NETWORK_URL_REMOVED]", text, flags=re.I)
    return text

def main(exe, out):
    raw = exe.read_bytes()[:MAX_BYTES]
    results = {}
    candidates = []
    for regex, dec in ((re.compile(rb"[\x20-\x7e]{4,320}"), "ascii"),
                       (re.compile(rb"(?:[\x20-\x7e]\x00){4,320}"), "utf-16le")):
        for m in regex.finditer(raw):
            if m.start() >= 0x1130000:
                candidates.append((m.start(),m.group().decode(dec,"replace")))
    for group, expr in KEYWORDS.items():
        regex = re.compile(expr, re.I)
        group_results = []
        seen = set()
        for offset, item in candidates:
            if not regex.search(item):
                continue
            if len(item) > 180 and not re.search("open.?adb|serialport|cp210",item,re.I):
                continue
            value = scrub(item)
            if value not in seen:
                group_results.append({"hex_offset":hex(offset),"s":value})
                seen.add(value)
            if len(group_results) >= MAX_PER_GROUP:
                break
        results[group] = {"observed_count":len(group_results),"hits":group_results}
    out.mkdir(parents=True,exist_ok=True)
    (out / "focus_strings.json").write_text(json.dumps({
        "target_name":exe.name,
        "bytes_scanned":len(raw),
        "method":"offline_ASCII_UTF16LE_short_strings",
        "evidence_type":"string_presence_only_not_behaviour_proof",
        "groups":results,
    },ensure_ascii=False,indent=2),encoding="utf-8")
    lines=["# Installed LIXIANGTOOLS targeted strings",
           "Main EXE examined without executing the application or connecting a car.",
           "Short embedded strings are not proof of specific protocol or action.", ""]
    for name,entry in results.items():
        lines.append("## "+name)
        for hit in entry["hits"]:
            lines.append("- "+hit["hex_offset"]+" "+hit["s"].replace(chr(96),"'"))
        lines.append("")
    (out / "FOCUSED.md").write_text("\n".join(lines),encoding="utf-8")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("exe",type=Path)
    ap.add_argument("--output",default="reports",type=Path)
    a=ap.parse_args()
    main(a.exe,a.output)
