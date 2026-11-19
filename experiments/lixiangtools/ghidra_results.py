"""Bounded and conservative projector for REA/Ghidra native Evidence.

No binaries, full disassembly, proprietary pseudocode, tokens, or source text
are returned. This is for user-authorized, offline interoperability research.
"""
import argparse
import json
from pathlib import Path

MAX_ENTRIES = 25
MAX_DEPTH = 5
KEYS = ("address","entry_point","name","procedure","name_or_address",
        "kind","size","type","classification","source_address",
        "target_address","symbol","error","code","message",
        "provider_id","status","available","reason")

def clip(x):
    if not isinstance(x,(str,int,float,bool,type(None))): return None
    if isinstance(x,str):
        if len(x)>150: return x[:147]+"..."
        return x
    return x

def focus(node,depth=0):
    if depth>=MAX_DEPTH: return {"truncated_depth":depth}
    if isinstance(node,list):
        return [focus(x,depth+1) for x in node[:MAX_ENTRIES]]
    if not isinstance(node,dict):
        return clip(node)
    result={}
    for k,v in node.items():
        if k in KEYS:
            if isinstance(v,(dict,list)):
                result[k]=focus(v,depth+1)
            else:
                result[k]=clip(v)
        elif k in ("procedures","matches","references","functions","locations","results","items","observations"):
            if isinstance(v,(list,dict)): result[k]=focus(v,depth+1)
        elif k in ("normalized_result","details","remediation","subject"):
            if isinstance(v,dict):result[k]=focus(v,depth+1)
    return result

def main(folder,out):
    names=[
      "ghidra-doctor.json",
      "ghidra-openadb-ui-bridge-string.json",
      "ghidra-uart-trigger-module-string.json",
      "ghidra-laconfig-payload-string.json",
      "ghidra-uart-trigger-ref.json",
      "ghidra-uart-trigger-code.json"
    ]
    observed={}
    for name in names:
        file=folder/name
        if not file.is_file():
            observed[name]={"state":"not_run"}
            continue
        try:
            obj=json.loads(file.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            observed[name]={"state":"invalid_json","detail":str(exc)[:100]}
            continue
        observed[name]={"state":"returned_json",
          "error_present":bool(obj.get("error")),
          "projected_fields":focus(obj)}
    result={"method":"reanative-ghidra12.1.4-read-only",
        "executed_on_vendor_executable":False,
        "car_connected":False,
        "reason":"Only native static analysis was requested",
        "outputs":observed,
        "limitations":[
          "A string xref does not prove a workflow executed",
          "No VIN or device was provided",
          "No firmware payload was generated, patched, signed or flashed",
          "Missing commands are unverified, not evidence of absence"
        ]}
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("folder",type=Path)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    main(a.folder,a.output)
