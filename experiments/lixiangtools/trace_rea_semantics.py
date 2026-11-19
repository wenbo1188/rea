"""Bounded, read-only REA semantic graph trace for the OPEN ADB UI.

Consumes the successful REA analyze-javascript-application JSON locally.
Only uploads short whitelisted labels / field names, not original JS or secrets.
"""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter, defaultdict, deque
from pathlib import Path

SEED = re.compile(r"startOpenAdb|check_license|op\.run|open_adb_v1|open_adb|/api/session/bootstrap",re.I)
FIELD_NAME = re.compile(r"^[a-zA-Z_$][\w$./:-]{0,95}$")
MAX_SEEDS = 18
MAX_VISITS = 140
MAX_DEGREE = 20
MAX_DEPTH = 2

def find_id(o):
    return next((o.get(k) for k in ("node_id","id") if isinstance(o.get(k),str)),None)

def clean_label(o):
    val=o.get("label") or ""
    # source code and tokens must not be copied to report
    if not isinstance(val,str): val=""
    val=re.sub(r"https?://[^\s]+","[URL]",val)
    if len(val)>110: val=val[:107]+"..."
    return val

def short_props(o):
    p=o.get("properties")
    if not isinstance(p,dict): return {}
    allow=("value","endpoint","event_name","name","method","property")
    out={}
    for k in allow:
        v=p.get(k)
        if isinstance(v,str) and len(v)<110 and (FIELD_NAME.fullmatch(v) or v in ("open_adb","open_adb_v1","op.run","op.check_license")):
            out[k]=v
    return out

def pick_edge_end(o,names):
    for n in names:
        v=o.get(n)
        if isinstance(v,str): return v
        if isinstance(v,dict):
            q=v.get("node_id") or v.get("id")
            if isinstance(q,str): return q
    return None

def main(src,dst):
    root=json.loads(src.read_text(encoding="utf-8"))
    sem=root.get("normalized_result",{}).get("semantic_graph",{})
    if not isinstance(sem,dict): raise RuntimeError("REA semantic_graph missing")
    nodes=sem.get("nodes",[])
    edges=sem.get("edges",sem.get("relations",[]))
    idx={i:o for o in nodes if isinstance(o,dict) and (i:=find_id(o))}
    seeds=[]
    for i,o in idx.items():
        p=short_props(o)
        if SEED.search(clean_label(o)) or any(SEED.search(v) for v in p.values()):
            seeds.append(i)
    sources=("source_node_id","from_node_id","source_id","from","source")
    targets=("target_node_id","to_node_id","target_id","to","target")
    adj=defaultdict(list)
    parsed=0
    for e in edges:
        if not isinstance(e,dict): continue
        a=pick_edge_end(e,sources)
        b=pick_edge_end(e,targets)
        if a not in idx or b not in idx: continue
        label=e.get("kind") or e.get("relation") or e.get("type") or e.get("relation_kind") or ""
        if not isinstance(label,str): label=""
        label=label[:80]
        adj[a].append((b,label,"out"))
        adj[b].append((a,label,"in"))
        parsed+=1
    selected=[]
    visited=set()
    queues=deque((s,0) for s in seeds[:MAX_SEEDS])
    while queues and len(selected)<MAX_VISITS:
        i,depth=queues.popleft()
        if i in visited: continue
        visited.add(i)
        o=idx[i]
        selected.append({"id":i,"kind":str(o.get("kind",""))[:80],
                         "label":clean_label(o),"fields":short_props(o),"depth":depth})
        if depth>=MAX_DEPTH:continue
        for neighbour,relation,direction in adj[i][:MAX_DEGREE]:
            if neighbour not in visited and neighbour in idx:
                queues.append((neighbour,depth+1))
    selected_ids={x["id"] for x in selected}
    short_edges=[]
    for i in selected_ids:
        for other,kind,direction in adj[i]:
            if other in selected_ids and direction=="out":
                short_edges.append({"src":i,"dst":other,"relation":kind})
    summary={
        "source":"REA packaged semantic_graph",
        "source_sha256":root.get("subject",{}).get("digest",{}).get("sha256"),
        "semantic_total_nodes":len(nodes),
        "semantic_total_edges":len(edges),
        "parsed_edges":parsed,
        "edge_sample_keys":list(edges[0])[:16] if edges else [],
        "seed_count":len(seeds),
        "visited_nodes":len(selected),
        "edge_count":len(short_edges),
        "selected_nodes":selected[:MAX_VISITS],
        "selected_edges":short_edges[:600],
        "limitations":[
            "Static AST relation graph, not executed UI or car-side behavior",
            "Two-hop bounded traversal, incomplete by design",
            "Vendor executable, JS sources, auth tokens, and secrets are not uploaded",
            "No native OpenAdbRunner call graph is established by this analysis",
        ]
    }
    dst.parent.mkdir(parents=True,exist_ok=True)
    dst.write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("source",type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    main(a.source,a.output)
