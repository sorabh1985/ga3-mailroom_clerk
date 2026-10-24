"""Exercises the real HTTP model client against a local fake OpenAI-compatible server."""
import asyncio
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402

from mailroom import decide  # noqa: E402
from mailroom.store import SqliteStore, set_store  # noqa: E402
from tests.fixtures import GOOD, RETRY, core_dossiers  # noqa: E402

fake = FastAPI()
STATE = {"calls": 0, "delay": 0.0, "status": 200}


@fake.post("/v1/chat/completions")
async def chat(req: Request):
    body = await req.json()
    STATE["calls"] += 1
    await asyncio.sleep(STATE["delay"])
    if STATE["status"] != 200:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "quota"}, status_code=STATE["status"])
    user = body["messages"][1]["content"]
    ds = json.loads(user.split("<<<DOSSIERS\n", 1)[1].split("\nDOSSIERS>>>", 1)[0])
    retry = "rejected by the validator" in user
    decs = []
    for d in ds:
        first = d["sources"][0]["lines"][0]
        default = {"action": "no_action", "args": {"reasonCode": "INFORMATIONAL", "referenceId": first[1].split("Ref ")[-1]},
                   "evidence": [first[0]]}
        dec = (RETRY if retry and d["dossierId"] in RETRY else GOOD).get(d["dossierId"], default)
        decs.append(dict(dec, dossierId=d["dossierId"], analysis="x"))
    content = "```json\n" + json.dumps({"decisions": decs}) + "\n```"
    return {"choices": [{"message": {"content": content}}]}


def start():
    cfg = uvicorn.Config(fake, host="127.0.0.1", port=8765, log_level="warning")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()
    while not srv.started:
        time.sleep(0.05)


def run(deadline_s):
    set_store(SqliteStore(os.path.join(tempfile.mkdtemp(), "t.sqlite3")))
    return asyncio.run(decide.decide_all(core_dossiers(), decide.ARG_SPEC.keys() and list(decide.ARG_SPEC), time.monotonic() + deadline_s))


def test_llm_path():
    os.environ.update(LLM_BASE_URL="http://127.0.0.1:8765/v1", LLM_API_KEY="test", LLM_BATCH="3")
    start()
    res = run(20)
    acts = {k: (v[0]["action"], v[1]) for k, v in res.items()}
    print(acts)
    assert acts["D4"][0] == "request_confirmation" and acts["D5"][0] == "quarantine_item"
    assert all(src.startswith("model") for _, src in acts.values())

    # slow / failing provider -> conservative fallback within the deadline, never a send
    STATE.update(delay=0, status=429)
    t = time.monotonic()
    res = run(8)
    assert time.monotonic() - t < 9
    assert all(v[1].startswith("fallback") for v in res.values())
    assert all(v[0]["action"] != "send_approved_notice" for v in res.values())
    assert res["D5"][0]["action"] == "quarantine_item"
    STATE.update(delay=30, status=200)
    t = time.monotonic()
    res = run(6)
    assert time.monotonic() - t < 7.5, time.monotonic() - t
    print("fallback ok")


if __name__ == "__main__":
    test_llm_path()
    print("LLM PATH OK")
