"""Read-only x64 PE direct RIP-relative cross-reference scanner.

Matches references to selected embedded text in Nuitka-compiled LIXIANGTOOLS.exe.
This recovers code -> literal reference evidence only; indirect access through
Nuitka module constants, structures, or data tables may be invisible.
"""
import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP

TARGETS = (
    "OpenAdbRunner.run",
    "startOpenAdb",
    "unlock.uart_trigger",
    "unlock.fastboot_io",
    "unlock.flash_writer",
    "laconfig_b64",
    "laconfig_patched.bin",
    "expected_vin",
    "/api/session/bootstrap",
    "op.check_license",
    "open_adb_v1",
    "CP2105_VID",
    "UART reset complete",
    "fastboot flash laconfig",
)
MAX_INST = 9_000_000

def main(src, out):
    pe = pefile.PE(str(src), fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664:
        raise RuntimeError("Target is not x86-64 PE")
    base = pe.OPTIONAL_HEADER.ImageBase
    raw = src.read_bytes()
    strings = []
    for term in TARGETS:
        for encoding in ("ascii","utf-16le"):
            pattern = term.encode(encoding)
            pos = 0
            count = 0
            while (pos := raw.find(pattern,pos)) >= 0 and count < 15:
                try:
                    rva = pe.get_rva_from_offset(pos)
                    if rva >= 0:
                        strings.append((base + rva,term,encoding,hex(pos)))
                        count += 1
                except Exception:
                    pass
                pos += len(pattern)
    strings.sort()
    addresses = [s[0] for s in strings]
    routines=[]
    for sec in pe.sections:
        if sec.Name.rstrip(b"\0").lower()==b".pdata":
            data=sec.get_data()
            for begin,end,unwind in struct.iter_unpack("<III",data[:(len(data)//12)*12]):
                if 0 < begin < end and end < pe.OPTIONAL_HEADER.SizeOfImage:
                    routines.append((base+begin,base+end,unwind))
    routines.sort()
    starts = [r[0] for r in routines]
    hits = []
    insns=0
    for sec in pe.sections:
        if sec.Name.rstrip(b"\0").lower()!=b".text":
            continue
        data=sec.get_data()
        cs=Cs(CS_ARCH_X86,CS_MODE_64)
        cs.detail=True
        cs.skipdata=True
        for op in cs.disasm(data,base+sec.VirtualAddress):
            insns+=1
            if insns > MAX_INST: break
            for operand in op.operands:
                if operand.type != CS_OP_MEM or operand.mem.base != X86_REG_RIP:
                    continue
                dest = op.address + op.size + operand.mem.disp
                i=bisect.bisect_left(addresses,dest-3)
                for candidate in strings[i:i+8]:
                    if abs(candidate[0]-dest)>12: break
                    f=bisect.bisect_right(starts,op.address)-1
                    runtime = routines[f] if f>=0 and op.address<routines[f][1] else None
                    hits.append({
                        "target":candidate[1],
                        "encoding":candidate[2],
                        "literal_va":hex(candidate[0]),
                        "code_va":hex(op.address),
                        "referenced_va":hex(dest),
                        "instruction":str(op.mnemonic)+" "+str(op.op_str),
                        "function_range":None if not runtime else [hex(runtime[0]),hex(runtime[1])],
                    })
                    if len(hits) > 3000: break
            if len(hits)>3000: break
        if insns>MAX_INST or len(hits)>3000: break
    d={"sha256":hashlib.sha256(raw).hexdigest(),
       "method":"read_only_direct_x64_rip_relative_references",
       "instructions_examined":insns,
       "literal_candidates":[{"name":s[1],"va":hex(s[0]),"encoding":s[2]} for s in strings],
       "runtime_function_ranges":len(routines),
       "direct_reference_hits":hits[:1000],
       "limitations":[
         "Only direct RIP-relative references, no indirect constant-table references.",
         "Reference is not proof the containing function executes.",
         "Function ranges are PE .pdata unwind ranges, not recovered Python methods.",
         "No read/write to a vehicle or vendor backend."
       ]}
    out.mkdir(parents=True,exist_ok=True)
    (out/"pe_direct_xrefs.json").write_text(json.dumps(d,indent=2),encoding="utf-8")
    lines=["# Native PE direct-reference evidence",
           "This is x64 code-reference data, not a complete Nuitka control-flow trace.",
           "",f"Instructions examined: {insns}; runtime ranges: {len(routines)}; cross-references: {len(hits)}.",""]
    for row in hits[:90]:
        lines.append("- "+row["target"]+" at "+row["code_va"]+" in "+str(row["function_range"])+": "+row["instruction"])
    if not hits:
        lines.append("No direct RIP-relative literal references recovered; likely constants are accessed indirectly.")
    (out/"pe_direct_xrefs.md").write_text("\n".join(lines),encoding="utf-8")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("exe",type=Path)
    ap.add_argument("--output",type=Path,default=Path("reports"))
    args=ap.parse_args()
    main(args.exe,args.output)
