"""Review the cached decisions after a Check (reads your Upstash store).

    export KV_REST_API_URL=...  KV_REST_API_TOKEN=...      (copy from Vercel > Storage)
    python tools/review.py                 # print every cached decision with cited lines
    python tools/review.py --purge D123    # forget one dossier's decision so it is re-decided

Purge only after fixing the prompt: a purged core dossier may get a different answer,
and the grader expects stable proposals across Checks.
"""
import json
import os
import sys

import httpx

URL = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")


def cmd(*args):
    r = httpx.post(URL, headers={"Authorization": f"Bearer {TOKEN}"}, json=list(args), timeout=20)
    r.raise_for_status()
    return r.json()["result"]


def all_keys():
    cursor, keys = "0", []
    while True:
        cursor, batch = cmd("SCAN", cursor, "MATCH", "dec:*", "COUNT", "200")
        keys += batch
        if cursor == "0":
            return keys


def main():
    if not (URL and TOKEN):
        sys.exit("Set KV_REST_API_URL and KV_REST_API_TOKEN first.")
    keys = all_keys()
    entries = [(k, json.loads(v)) for k, v in zip(keys, cmd("MGET", *keys) if keys else []) if v]
    if len(sys.argv) == 3 and sys.argv[1] == "--purge":
        hit = [k for k, e in entries if e.get("dossier", {}).get("dossierId") == sys.argv[2]]
        for k in hit:
            cmd("DEL", k)
        print(f"purged {len(hit)} entr{'y' if len(hit) == 1 else 'ies'}")
        return
    counts = {}
    for k, e in sorted(entries, key=lambda x: (x[1].get("dossier", {}).get("partition", ""), x[1]["core"]["action"])):
        d, core = e.get("dossier", {}), e["core"]
        counts[core["action"]] = counts.get(core["action"], 0) + 1
        lines = {ln["lineId"]: (s["kind"], s["provenance"], ln["text"]) for s in d.get("sources", []) for ln in s["lines"]}
        print("=" * 100)
        print(f"{d.get('dossierId')}  [{d.get('partition')}]  mailbox={d.get('mailbox')}")
        print(f"objective: {d.get('objective')}")
        for s in d.get("sources", []):
            print(f"  -- {s['sourceId']} kind={s['kind']} provenance={s['provenance']} title={s['title']}")
            for ln in s["lines"]:
                mark = ">>" if ln["lineId"] in core["evidence"] else "  "
                print(f"   {mark} {ln['lineId']}: {ln['text'][:220]}")
        print(f"DECISION: {core['action']}  target={json.dumps(core['target'])}")
        print(f"          payload={json.dumps(core['payload'], ensure_ascii=False)}")
        print(f"          why: {e.get('analysis')}")
    print("=" * 100)
    print("action counts:", counts)


if __name__ == "__main__":
    main()
