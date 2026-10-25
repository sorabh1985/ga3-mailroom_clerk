"""Export every dossier the grader sent, with the decision currently stored for it.

    export KV_REST_API_URL=...  KV_REST_API_TOKEN=...
    python tools/export.py            # writes export.json

The dossiers are the exam's synthetic cases. No keys or tokens are written to the file.
"""
import json
import os
import sys

import httpx

URL = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")


def cmd(*args):
    r = httpx.post(URL, headers={"Authorization": f"Bearer {TOKEN}"}, json=list(args), timeout=30)
    r.raise_for_status()
    return r.json()["result"]


def scan(pattern):
    cursor, keys = "0", []
    while True:
        cursor, batch = cmd("SCAN", cursor, "MATCH", pattern, "COUNT", "500")
        keys += batch
        if cursor == "0":
            return keys


def mget(keys):
    out = []
    for i in range(0, len(keys), 50):
        out += cmd("MGET", *keys[i:i + 50])
    return out


def main():
    if not (URL and TOKEN):
        sys.exit("Set KV_REST_API_URL and KV_REST_API_TOKEN first.")
    items = {}
    dec_keys = scan("dec:*")
    for k, v in zip(dec_keys, mget(dec_keys)):
        if v:
            e = json.loads(v)
            d = e.get("dossier")
            if d:
                items[d["dossierId"]] = {"state": "decided", "dossier": d, "decision": e["core"], "why": e.get("analysis")}
    pend_keys = scan("pend:*")
    for k, v in zip(pend_keys, mget(pend_keys)):
        if v:
            d = json.loads(v)["dossier"]
            items.setdefault(d["dossierId"], {"state": "pending", "dossier": d, "decision": None, "why": None})
    commits = json.loads(cmd("GET", "diag:commits") or "[]")
    out = {"count": len(items), "items": sorted(items.values(), key=lambda x: (x["dossier"]["partition"], x["dossier"]["dossierId"])),
           "recentCommits": commits}
    with open("export.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    parts = {}
    for it in out["items"]:
        key = (it["dossier"]["partition"], it["state"])
        parts[key] = parts.get(key, 0) + 1
    print(f"wrote export.json: {out['count']} dossiers", parts)


if __name__ == "__main__":
    main()
