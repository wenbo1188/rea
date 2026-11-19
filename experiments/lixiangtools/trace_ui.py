"""Bounded read-only symbol/UI inspection of the installed LIXIANGTOOLS client.

Only emits short contexts and offline metadata; no client execution or serial/network
calls. Nuitka-compiled Python literal neighborhoods are NOT a recovered call graph.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ANCHORS = [
    "OpenAdbRunner.run", "OpenAdbRunner._pre_reboot",
    "OpenAdbRunner._pick_com", "unlock.uart_trigger",
    "unlock.fastboot_io", "unlock.flash_writer",
    "laconfig_b64", "laconfig_patched.bin", "laconfig",
    "startOpenAdb", "cancelOpenAdb", "lixiangtools.openadb",
    "/api/session/bootstrap", "operator_token", "uart_trigger",
    "CP2105_VID", "CP2105_PID", "api.lixiang.tools",
    "version-bootloader", "ota_swin", "8.7",
    "unlock.server_client", "server_client.py", "BuildRequest", "BuildResponse",
    "post_build", "unlock.flow", "run_open_adb", "verify_restore_blob",
    "write_and_flash", "skip_uart_trigger", "skip_uart",
    "getvar", "expected_vin", "expected_serialno", "expected_sha256",
]
UI_TERMS = [
    "startOpenAdb", "cancelOpenAdb", "OPEN ADB", "openadb",
    "hasToken", "remoteBearer", "pinUnlock", "auth.refresh",
    "Bridge.", "api/session/bootstrap", "laconfig", "uart",
]
MAX_MAIN_BYTES = 32*1024*1024
MAX_PER_ANCHOR = 10
MAX_UI_MATCHES = 75

def safe(s):
    s = re.sub(r"(?i)(?:bearer\s+)[A-Za-z0-9\-_\.]+", "Bearer [REDACTED]", s)
    s = re.sub(r"(?i)((?:token|password|secret|api_key)\s*[=:]\s*)[^\s,;)}]+", r"\1[REDACTED]", s)
    s = re.sub(r"https?://[^\s\}\)\"']+", "[NETWORK_URL]", s)
    return s.replace("\r", " ").replace("\n", " ")

def strings(data):
    found = []
    for rx, encoding in [
        (re.compile(rb"[\x20-\x7e]{4,270}"), "ascii"),
        (re.compile(rb"(?:[\x20-\x7e]\x00){4,270}"), "utf-16le"),
    ]:
        for match in rx.finditer(data):
            found.append((match.start(), match.group().decode(encoding, "replace")))
    return sorted(found)

def main(install, out):
    out.mkdir(parents=True, exist_ok=True)
    main = install/"LIXIANGTOOLS.exe"
    result = {"binary":{}, "literal_neighborhoods":{}, "ui":{}, "limitations":[
        "Neighboring constants can belong to separate functions or modules.",
        "Static UI text does not prove that a feature is callable or passes authorization.",
        "No serial device, vehicle, API login, unlock payload, or flash operation was executed."
    ]}
    if main.is_file():
        raw = main.read_bytes()[:MAX_MAIN_BYTES]
        ss = strings(raw)
        result["binary"] = {"size_bytes":main.stat().st_size,
            "sha256":hashlib.sha256(raw).hexdigest(),
            "literal_count":len(ss)}
        for term in ANCHORS:
            matches = [i for i, (_, val) in enumerate(ss) if term.lower() in val.lower()]
            rows = []
            for i in matches[:MAX_PER_ANCHOR]:
                offs, val = ss[i]
                nearby = [{"offset":hex(ss[j][0]),"text":safe(ss[j][1])[:130]}
                          for j in range(max(0,i-5),min(len(ss),i+6))
                          if abs(ss[j][0]-offs) < 650]
                rows.append({"offset":hex(offs),"anchor":safe(val)[:130],
                             "nearby":nearby})
            result["literal_neighborhoods"][term]={"match_count":len(matches),"samples":rows}
    for rel in ("boot_fallback.js","boot_fallback.html","x01diag/web/index.html"):
        p=install/rel
        if not p.exists() or p.stat().st_size > 2*1024*1024:
            continue
        txt=p.read_text(encoding="utf-8",errors="replace")
        snippets=[]
        for term in UI_TERMS:
            rx=re.compile(re.escape(term),re.I)
            matches=list(rx.finditer(txt))
            for m in matches[:MAX_PER_ANCHOR]:
                snippet=safe(txt[max(0,m.start()-160):min(len(txt),m.end()+220)])
                snippets.append({"term":term,"offset":m.start(),"excerpt":snippet[:400]})
        extended = []
        for exact in ("window.bridge.startOpenAdb", "r.params || {}", "window.bridge.callAsync", "open_adb"):
            for match in list(re.finditer(re.escape(exact), txt, flags=re.I))[:3]:
                extended.append({"anchor":exact,"offset":match.start(),
                                 "excerpt":safe(txt[max(0,match.start()-2600):min(len(txt),match.end()+900)])})
        snippets.sort(key=lambda x:x["offset"])
        result["ui"][rel]={"size_bytes":p.stat().st_size,
                            "sha256":hashlib.sha256(p.read_bytes()).hexdigest(),
                            "matches":snippets[:MAX_UI_MATCHES],
                            "total_candidate_matches":len(snippets),
                            "openadb_extended":extended[:12]}
    (out/"trace_ui_symbols.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["# Static UI and Nuitka literal proximity evidence", "",
           "All data are read-only observations of installed binaries/UI. Proximity is not control flow.", ""]
    lines.append("## UI sources")
    for source,d in result["ui"].items():
        lines.append(f"### {source} ({d['size_bytes']} bytes)")
        for row in d["matches"]:
            lines.append(f"- {row['term']} at {row['offset']}: {row['excerpt']}")
        lines.append("")
    lines.append("## Main executable anchors")
    for k,v in result["literal_neighborhoods"].items():
        lines.append(f"### {k} (matches: {v['match_count']})")
        for sample in v["samples"][:3]:
            lines.append(f"- {sample['offset']}: {sample['anchor']}")
            lines.extend(f"    - {x['offset']}: {x['text']}" for x in sample["nearby"])
        lines.append("")
    (out/"trace_ui_symbols.md").write_text("\n".join(lines),encoding="utf-8")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("installed",type=Path)
    parser.add_argument("--output",type=Path,default=Path("reports"))
    args=parser.parse_args()
    main(args.installed,args.output)
