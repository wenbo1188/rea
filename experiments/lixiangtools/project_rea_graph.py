"""Project a bounded summary from successful REA JavaScript graph Evidence.
Does not execute or modify target. Avoid uploading unbounded vendor UI graphs.
"""
import argparse
import json
import re
from pathlib import Path

PAT = re.compile(r"open_adb|openadb|startOpenAdb|check_license|pipeline|op\.run|bridge", re.I)
MAX_GROUPS = 15
MAX_NODES_PER_GROUP = 80

def main(source, output):
    root=json.loads(source.read_text(encoding="utf-8"))
    tables=[]
    def visit(obj,path="root",depth=0):
        if depth>9 or len(tables)>35: return
        if isinstance(obj,dict):
            for k,v in obj.items():
                if k in ("nodes","relations","edges") and isinstance(v,list):
                    tables.append((path+"."+k,v))
                elif isinstance(v,dict):
                    visit(v,path+"."+k,depth+1)
    visit(root)
    rows=[]
    for path,vals in tables[:MAX_GROUPS]:
        matches=[]
        for i,v in enumerate(vals):
            if not isinstance(v,dict): continue
            # Only scan small identifying fields, not full node contents.
            candidates=[]
            for k in ("label","name","kind","event_name","endpoint","type","operation","field","value","id","call_name","method"):
                if k in v and isinstance(v[k],str):
                    candidates.append(v[k][:250])
            for child_key in ("properties","identity"):
                child=v.get(child_key)
                if isinstance(child,dict):
                    for k in ("label","name","event_name","endpoint","value","kind","operation","method","path"):
                        if isinstance(child.get(k),str):
                            candidates.append(child[k][:250])
            candidate=" | ".join(candidates)
            if PAT.search(candidate):
                matches.append({"index":i,"id":v.get("node_id") or v.get("relation_id") or v.get("edge_id"),
                      "kind":v.get("kind"),"label":v.get("label"),"names":candidate[:420]})
            if len(matches)>=MAX_NODES_PER_GROUP:break
        rows.append({"collection":path,"total_count":len(vals),
                     "matches_capped":len(matches),
                     "matches":matches})
    status={"schema":"rea-static-javascript-projection",
            "source_size":source.stat().st_size,
            "is_error":bool(root.get("error")),
            "top_keys":list(root)[:24],
            "collections":rows,
            "note":"Semantic label matches are not proof of dynamic execution; inspect full evidence privately for trace."}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding="utf-8")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("graph",type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    main(args.graph,args.output)
