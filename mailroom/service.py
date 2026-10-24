"""HTTP service: one public endpoint, two POST operations (propose, commit)."""
import asyncio
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Request
from fastapi.responses import Response

from . import decide as decide_mod
from .canon import (call_id_for, canonical, digest, dossier_fingerprint, input_digest,
                    proposal_digest, sha256_hex)
from .schema import (PROFILE, BadRequest, b64_decode_sig, b64url_decode, parse_json,
                     validate_commit, validate_envelope, validate_propose)
from .store import dumps, get_store

MAX_BODY = 4 * 1024 * 1024
MAX_RESPONSE = 512 * 1024
PROPOSE_BUDGET = float(os.environ.get("PROPOSE_BUDGET_SECONDS", "46"))

app = FastAPI(redirect_slashes=False, docs_url=None, redoc_url=None, openapi_url=None)

# Tests may inject a fake model here (no network).
DECIDER = None


def jresp(obj_or_bytes, status=200):
    body = obj_or_bytes if isinstance(obj_or_bytes, bytes) else json.dumps(
        obj_or_bytes, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return Response(content=body, status_code=status, media_type="application/json",
                    headers={"Cache-Control": "no-store"})


def err(status, code, message):
    return jresp({"profile": PROFILE, "status": "error", "error": code, "message": message}, status)


def ekey(evaluation_id, part):
    return f"ev:{sha256_hex(evaluation_id.encode('utf-8'))}:{part}"


@app.api_route("/{path:path}", methods=["GET", "HEAD"])
async def health(path: str):
    s = get_store()
    from .llm import config
    cfg = config()
    return jresp({"ok": True, "service": "mailroom-action-gate", "profile": PROFILE,
                  "store": s.kind, "model": cfg["model"], "modelConfigured": bool(cfg["api_key"]),
                  "promptVersion": decide_mod.PROMPT_VERSION})


@app.api_route("/{path:path}", methods=["PUT", "PATCH", "DELETE", "OPTIONS"])
async def other(path: str):
    return err(405, "method_not_allowed", "use POST")


@app.post("/{path:path}")
async def handle(request: Request, path: str):
    t0 = time.monotonic()
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        return err(413, "body_too_large", "request body too large")
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            return err(413, "body_too_large", "request body too large")
    try:
        obj = parse_json(bytes(raw))
        op = validate_envelope(obj)
        if op == "propose":
            validate_propose(obj)
        else:
            validate_commit(obj)
    except BadRequest as e:
        return err(e.status, e.code, e.message)
    try:
        if op == "propose":
            return await propose(obj, t0)
        return await commit(obj)
    except BadRequest as e:
        return err(e.status, e.code, e.message)
    except Exception as e:  # noqa: BLE001
        print("internal error:", repr(e))
        return err(500, "internal_error", "internal error")


# ------------------------------------------------------------------ propose
async def propose(obj, t0):
    store = get_store()
    ev_id = obj["evaluationId"]
    req_hash = digest(obj)
    rec_key, lock_key = ekey(ev_id, "propose"), ekey(ev_id, "plock")

    existing = await store.get(rec_key)
    if existing:
        rec = json.loads(existing)
        if rec["reqHash"] != req_hash:
            raise BadRequest(409, "conflict", "evaluationId already used with different content")
        return jresp(rec["response"].encode("utf-8"))

    if not await store.set_nx(lock_key, req_hash, ex=120):
        holder = await store.get(lock_key)
        if holder and holder != req_hash:
            raise BadRequest(409, "conflict", "evaluationId already used with different content")
        # identical request already in flight: wait for its stored result
        while time.monotonic() - t0 < 52:
            await asyncio.sleep(0.5)
            existing = await store.get(rec_key)
            if existing:
                rec = json.loads(existing)
                if rec["reqHash"] != req_hash:
                    raise BadRequest(409, "conflict", "evaluationId already used with different content")
                return jresp(rec["response"].encode("utf-8"))
        raise BadRequest(503, "in_progress", "identical request still in progress")

    try:
        return await _propose_locked(obj, t0, store, ev_id, req_hash, rec_key)
    except BaseException:
        await store.delete(lock_key)  # let an identical retry run instead of waiting on a dead lock
        raise


async def _propose_locked(obj, t0, store, ev_id, req_hash, rec_key):
    dossiers = obj["dossiers"]
    allowed = obj["allowedActions"]
    deadline = t0 + PROPOSE_BUDGET
    decisions = await decide_mod.decide_all(dossiers, allowed, deadline, decider=DECIDER)

    proposals, index = [], {}
    for d in dossiers:
        core, src = decisions[d["dossierId"]]
        p = {
            "dossierId": d["dossierId"],
            "callId": call_id_for(d["dossierId"], dossier_fingerprint(d)),
            "action": core["action"],
            "target": core["target"],
            "payload": core["payload"],
            "evidence": core["evidence"],
        }
        proposals.append(p)
        index[d["dossierId"]] = {"callId": p["callId"], "action": p["action"],
                                 "proposalDigest": proposal_digest(p), "source": src}
        print(f"[propose] {d['partition']} {d['dossierId']} -> {p['action']} ({src})")

    response = {
        "profile": PROFILE,
        "evaluationId": ev_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest(dossiers),
        "proposals": proposals,
    }
    resp_text = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
    if len(resp_text.encode("utf-8")) > MAX_RESPONSE:
        raise BadRequest(500, "response_too_large", "response would exceed 512 KiB")
    record = {"reqHash": req_hash, "response": resp_text, "inputDigest": response["inputDigest"],
              "jwk": obj["receiptVerifier"]["publicKeyJwk"], "index": index, "at": int(time.time())}
    await store.set(rec_key, dumps(record))  # persist before replying
    return jresp(resp_text.encode("utf-8"))


# ------------------------------------------------------------------ commit
def verify_signature(jwk, commit_obj, receipt) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
        sig = b64_decode_sig(receipt["receiptSignature"])
        if len(sig) != 64:
            return False
        inner = {k: v for k, v in receipt.items() if k != "receiptSignature"}
        msg = canonical({"profile": commit_obj["profile"], "evaluationId": commit_obj["evaluationId"],
                         "inputDigest": commit_obj["inputDigest"], "receipt": inner})
        key.verify(sig, msg)
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


async def commit(obj):
    store = get_store()
    ev_id = obj["evaluationId"]
    req_hash = digest(obj)
    c_key = ekey(ev_id, "commit")

    existing = await store.get(c_key)
    if existing:
        rec = json.loads(existing)
        if rec["reqHash"] != req_hash:
            raise BadRequest(409, "conflict", "evaluation already committed with different receipts")
        return jresp(rec["response"].encode("utf-8"))

    praw = await store.get(ekey(ev_id, "propose"))
    if not praw:
        raise BadRequest(404, "unknown_evaluation", "no proposal stored for this evaluationId")
    prec = json.loads(praw)
    if obj["inputDigest"] != prec["inputDigest"]:
        raise BadRequest(409, "digest_mismatch", "inputDigest does not match the stored proposal")

    receipts = obj["receipts"]
    index = prec["index"]
    seen_d, seen_r, seen_s = set(), set(), set()
    for i, r in enumerate(receipts):
        if r["dossierId"] in seen_d or r["receiptId"] in seen_r or r["receiptSignature"] in seen_s:
            raise BadRequest(422, "duplicate_receipt", f"receipts[{i}] duplicates another receipt")
        seen_d.add(r["dossierId"]); seen_r.add(r["receiptId"]); seen_s.add(r["receiptSignature"])
        p = index.get(r["dossierId"])
        if p is None:
            raise BadRequest(409, "unknown_proposal", f"receipts[{i}] refers to an unknown dossier")
        if r["callId"] != p["callId"] or r["action"] != p["action"] or r["proposalDigest"] != p["proposalDigest"]:
            raise BadRequest(409, "proposal_mismatch", f"receipts[{i}] does not match the persisted proposal")
    if seen_d != set(index):
        raise BadRequest(422, "missing_receipts", "commit must contain exactly one receipt per proposal")

    for i, r in enumerate(receipts):  # all-or-nothing: verify every signature first
        if not verify_signature(prec["jwk"], obj, r):
            raise BadRequest(422, "invalid_signature", f"receipts[{i}] has an invalid signature")

    outcomes = [{
        "dossierId": r["dossierId"], "callId": r["callId"], "action": r["action"],
        "proposalDigest": r["proposalDigest"], "receiptId": r["receiptId"],
        "status": "executed" if r["accepted"] is True else "rejected",
    } for r in receipts]
    response = {"profile": PROFILE, "evaluationId": ev_id, "status": "completed",
                "inputDigest": obj["inputDigest"], "outcomes": outcomes}
    resp_text = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
    record = {"reqHash": req_hash, "response": resp_text, "receipts": receipts, "at": int(time.time())}
    if not await store.set_nx(c_key, dumps(record)):
        other = json.loads(await store.get(c_key))
        if other["reqHash"] != req_hash:
            raise BadRequest(409, "conflict", "evaluation already committed with different receipts")
        return jresp(other["response"].encode("utf-8"))
    print(f"[commit] {ev_id}: {sum(o['status'] == 'executed' for o in outcomes)} executed, "
          f"{sum(o['status'] == 'rejected' for o in outcomes)} rejected")
    return jresp(resp_text.encode("utf-8"))
