"""Decide the real exam dossiers locally (no Vercel time limit, no Check used), compare with
reference answers, and store the decisions in the shared cache so the next Check reuses them.

    export LLM_API_KEY=...                       # your Gemini key
    export LLM_MODEL=gemini-3-flash-preview LLM_FALLBACK_MODEL=gemini-3.1-flash-lite
    export KV_REST_API_URL=...  KV_REST_API_TOKEN=...   # so results are cached for the Check
    python tools/offline_eval.py export.json            # decides only what is not cached yet
    python tools/offline_eval.py export.json --fresh    # re-decide everything with the current prompt

tools/gold.json holds reference answers derived from each dossier's own signed policy. They are
used only for this report, never by the service.
"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailroom import decide  # noqa: E402
from mailroom.store import get_store  # noqa: E402

ACTIONS = ["create_draft", "update_internal_record", "send_approved_notice",
           "request_confirmation", "quarantine_item", "no_action"]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    fresh = "--fresh" in sys.argv
    here = os.path.dirname(os.path.abspath(__file__))
    gold = json.load(open(os.path.join(here, "gold.json")))
    items = json.load(open(sys.argv[1], encoding="utf-8"))["items"]
    dossiers = [i["dossier"] for i in items if i["dossier"]["dossierId"] in gold]
    store = get_store()
    print(f"{len(dossiers)} dossiers, store={store.kind}, model={os.environ.get('LLM_MODEL')}, "
          f"fallback={os.environ.get('LLM_FALLBACK_MODEL')}, prompt={decide.PROMPT_VERSION}")
    t = time.monotonic()
    res = asyncio.run(decide.decide_all(dossiers, ACTIONS, time.monotonic() + 600, use_cache=not fresh))
    print(f"done in {time.monotonic() - t:.0f}s\n")

    score = {"action": 0, "target+payload": 0, "evidence sufficient": 0, "evidence exact": 0, "fallback": 0}
    rows = []
    for d in dossiers:
        core, src = res[d["dossierId"]]
        g = gold[d["dossierId"]]
        ok_a = core["action"] == g["action"]
        ok_p = ok_a and core["target"] == g["target"] and core["payload"] == g["payload"]
        ok_s = set(g["evidence"]) <= set(core["evidence"])
        ok_e = set(g["evidence"]) == set(core["evidence"])
        score["action"] += ok_a; score["target+payload"] += ok_p
        score["evidence sufficient"] += ok_s; score["evidence exact"] += ok_e
        score["fallback"] += src.startswith("fallback")
        if not (ok_p and ok_e):
            rows.append((d, core, g, src))
    n = len(dossiers)
    for k, v in score.items():
        print(f"  {k:<22} {v}/{n}")
    print()
    for d, core, g, src in rows:
        lines = {l["lineId"]: l["text"] for s in d["sources"] for l in s["lines"]}
        print("=" * 100)
        print(f"{d['dossierId']} [{d['partition']}] source={src[:80]}")
        if core["action"] != g["action"] or core["target"] != g["target"] or core["payload"] != g["payload"]:
            print(f"  got      {core['action']} {json.dumps(core['target'])} {json.dumps(core['payload'])}")
            print(f"  expected {g['action']} {json.dumps(g['target'])} {json.dumps(g['payload'])}")
        missing = [x for x in g["evidence"] if x not in core["evidence"]]
        extra = [x for x in core["evidence"] if x not in g["evidence"]]
        for x in missing:
            print(f"  evidence missing: {x}: {lines.get(x, '')[:150]}")
        for x in extra:
            print(f"  evidence extra:   {x}: {lines.get(x, '')[:150]}")


if __name__ == "__main__":
    main()
