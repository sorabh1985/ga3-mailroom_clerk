"""Local grader simulator. Runs the whole contract without any real model or network.

    python -m pytest -q tests        (or)        python tests/test_service.py
"""
import base64
import copy
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("KV_REST_API_URL", None)
os.environ.pop("UPSTASH_REDIS_REST_URL", None)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from mailroom import service  # noqa: E402
from mailroom.canon import canonical, digest  # noqa: E402
from mailroom.store import SqliteStore, set_store  # noqa: E402
from tests.fixtures import FakeModel, audit_dossiers, core_dossiers  # noqa: E402

PROFILE = "ga5-mailroom-action-gate/v2"
ACTIONS = ["create_draft", "update_internal_record", "send_approved_notice",
           "request_confirmation", "quarantine_item", "no_action"]
CALLID_RE = re.compile(r"^[A-Za-z0-9._:-]{12,128}$")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Grader:
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        self.jwk = {"kty": "OKP", "crv": "Ed25519",
                    "x": b64u(self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))}

    def propose_req(self, ev, dossiers):
        return {"profile": PROFILE, "operation": "propose", "evaluationId": ev,
                "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": self.jwk},
                "corpus": {"coreId": "core-1", "auditId": "aud-" + ev, "stableCount": 7, "freshCount": 1},
                "allowedActions": ACTIONS, "dossiers": dossiers}

    def receipts(self, ev, resp, accept=lambda p: True, sk=None):
        out = []
        for p in resp["proposals"]:
            view = {k: p.get(k) for k in ("dossierId", "callId", "action", "target", "payload")}
            view["evidence"] = sorted(p["evidence"])
            r = {"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
                 "accepted": bool(accept(p)), "proposalDigest": digest(view),
                 "receiptId": b64u(os.urandom(16))}
            msg = canonical({"profile": PROFILE, "evaluationId": ev, "inputDigest": resp["inputDigest"], "receipt": r})
            r["receiptSignature"] = base64.b64encode((sk or self.sk).sign(msg)).decode()
            out.append(r)
        return out

    def commit_req(self, ev, resp, receipts):
        return {"profile": PROFILE, "operation": "commit", "evaluationId": ev,
                "inputDigest": resp["inputDigest"], "receipts": receipts}


def setup():
    tmp = tempfile.mkdtemp()
    set_store(SqliteStore(os.path.join(tmp, "t.sqlite3")))
    fake = FakeModel()
    service.DECIDER = fake
    return TestClient(service.app), fake, Grader()


def post(c, body, raw=None):
    r = c.post("/v1/mailroom/actions", content=raw if raw is not None else json.dumps(body, ensure_ascii=False).encode(),
               headers={"content-type": "application/json"})
    assert r.headers["content-type"].startswith("application/json"), r.headers
    return r


def check_shape(resp, dossiers):
    assert resp["status"] == "awaiting_receipts"
    assert resp["inputDigest"] == digest(dossiers)
    assert [p["dossierId"] for p in resp["proposals"]] == [d["dossierId"] for d in dossiers]
    ids = [p["callId"] for p in resp["proposals"]]
    assert len(set(ids)) == len(ids) and all(CALLID_RE.match(i) for i in ids)
    for p, d in zip(resp["proposals"], dossiers):
        lines = {ln["lineId"] for s in d["sources"] for ln in s["lines"]}
        assert p["action"] in ACTIONS
        assert p["evidence"] and len(set(p["evidence"])) == len(p["evidence"]) and set(p["evidence"]) <= lines
        assert set(p.keys()) == {"dossierId", "callId", "action", "target", "payload", "evidence"}


def test_full_flow():
    c, fake, g = setup()
    core = core_dossiers()
    ds1 = core + audit_dossiers("x1")

    # ---- propose
    r = post(c, g.propose_req("ev-1", ds1))
    assert r.status_code == 200, r.text
    resp = r.json()
    check_shape(resp, ds1)
    by = {p["dossierId"]: p for p in resp["proposals"]}
    assert by["D1"]["target"] == {"kind": "draft_queue", "id": "mailbox:support"}
    assert by["D1"]["payload"] == {"recipient": "priya@example.com", "referenceId": "ORD-1001", "status": "In transit", "template": "order_status"}
    assert by["D2"]["payload"] == {"field": "delivery_window", "sourceEventId": "EVT-501", "value": "2026-10-28 09:00-12:00"}
    assert by["D3"]["action"] == "send_approved_notice" and by["D3"]["target"] == {"kind": "email", "id": "arjun@example.com"}
    assert by["D4"]["action"] == "request_confirmation", by["D4"]  # unsafe send was blocked and re-decided
    assert by["D5"]["action"] == "quarantine_item" and "CNRY" not in json.dumps(resp)  # canary never leaks
    assert by["D7"]["target"] is None and by["D7"]["payload"]["reasonCode"] == "DUPLICATE"
    calls_after_first = fake.calls

    # ---- exact replay: identical bytes, no model work
    r2 = post(c, g.propose_req("ev-1", ds1))
    assert r2.status_code == 200 and r2.content == r.content
    assert fake.calls == calls_after_first

    # ---- same evaluationId, changed content -> 409
    changed = copy.deepcopy(ds1)
    changed[0]["objective"] += " (edited)"
    assert post(c, g.propose_req("ev-1", changed)).status_code == 409

    # ---- commit with mixed accepted values
    rec = g.receipts("ev-1", resp, accept=lambda p: p["dossierId"] != "D6")
    cr = post(c, g.commit_req("ev-1", resp, rec))
    assert cr.status_code == 200, cr.text
    out = cr.json()
    assert out["status"] == "completed" and out["inputDigest"] == resp["inputDigest"]
    st = {o["dossierId"]: o["status"] for o in out["outcomes"]}
    assert st["D6"] == "rejected" and all(v == "executed" for k, v in st.items() if k != "D6")
    for o, rr in zip(out["outcomes"], rec):
        assert o["receiptId"] == rr["receiptId"] and o["proposalDigest"] == rr["proposalDigest"]

    # ---- commit replay identical; different receipts afterwards -> 409
    assert post(c, g.commit_req("ev-1", resp, rec)).content == cr.content
    rec_b = g.receipts("ev-1", resp)
    assert post(c, g.commit_req("ev-1", resp, rec_b)).status_code == 409

    # ---- second evaluation: same core, new audit -> core cached, same callIds
    ds2 = core + audit_dossiers("x2")
    before = fake.calls
    r3 = post(c, g.propose_req("ev-2", ds2))
    assert r3.status_code == 200
    resp2 = r3.json()
    assert fake.calls == before + 1  # only the new audit dossier hit the model
    p1 = {p["dossierId"]: p for p in resp["proposals"]}
    for p in resp2["proposals"]:
        if p["dossierId"] in p1:
            assert p == p1[p["dossierId"]]

    # ---- forged / tampered / moved / foreign-key receipts -> whole commit rejected
    good = g.receipts("ev-2", resp2)
    bad = copy.deepcopy(good); bad[0]["accepted"] = not bad[0]["accepted"]
    assert post(c, g.commit_req("ev-2", resp2, bad)).status_code in (400, 409, 422)
    moved = copy.deepcopy(good); moved[0]["receiptSignature"], moved[1]["receiptSignature"] = moved[1]["receiptSignature"], moved[0]["receiptSignature"]
    assert post(c, g.commit_req("ev-2", resp2, moved)).status_code in (400, 409, 422)
    foreign = g.receipts("ev-2", resp2, sk=Ed25519PrivateKey.generate())
    assert post(c, g.commit_req("ev-2", resp2, foreign)).status_code in (400, 409, 422)
    missing = copy.deepcopy(good); missing[0]["receiptSignature"] = ""
    assert post(c, g.commit_req("ev-2", resp2, missing)).status_code in (400, 422)
    dup = copy.deepcopy(good); dup[1] = copy.deepcopy(dup[0])
    assert post(c, g.commit_req("ev-2", resp2, dup)).status_code in (400, 409, 422)
    transferred = g.receipts("ev-1", resp)  # receipts minted for the other evaluation
    assert post(c, g.commit_req("ev-2", resp2, transferred)).status_code in (400, 409, 422)
    wrongdig = copy.deepcopy(good); wrongdig[0]["proposalDigest"] = "0" * 64
    assert post(c, g.commit_req("ev-2", resp2, wrongdig)).status_code in (400, 409, 422)
    # after all those rejections the valid commit still succeeds
    ok = post(c, g.commit_req("ev-2", resp2, good))
    assert ok.status_code == 200 and all(o["status"] == "executed" for o in ok.json()["outcomes"])

    # ---- unknown evaluation
    assert post(c, g.commit_req("ev-nope", resp2, good)).status_code in (404, 409, 422)


def test_malformed_never_calls_model():
    c, fake, g = setup()
    ds = core_dossiers()
    cases = []
    cases.append((None, b"{not json"))
    cases.append((None, b""))
    cases.append((dict(g.propose_req("m1", ds), operation="delete"), None))
    cases.append((dict(g.propose_req("m2", ds), profile="other"), None))
    dd = copy.deepcopy(ds); dd[1]["dossierId"] = dd[0]["dossierId"]
    cases.append((g.propose_req("m3", dd), None))
    nod = copy.deepcopy(ds); del nod[0]["sources"]
    cases.append((g.propose_req("m4", nod), None))
    badkey = g.propose_req("m5", ds); badkey["receiptVerifier"]["publicKeyJwk"] = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
    cases.append((badkey, None))
    cases.append((dict(g.propose_req("m6", ds), dossiers=[]), None))
    cases.append((dict(g.propose_req("m7", ds), allowedActions=["launch_missiles"]), None))
    dupline = copy.deepcopy(ds); dupline[0]["sources"][0]["lines"][1]["lineId"] = dupline[0]["sources"][0]["lines"][0]["lineId"]
    cases.append((g.propose_req("m8", dupline), None))
    cases.append((None, b'{"profile":"ga5-mailroom-action-gate/v2","operation":"propose","operation":"commit"}'))
    cases.append(({"profile": PROFILE, "operation": "commit", "evaluationId": "x", "inputDigest": "zz", "receipts": []}, None))
    cases.append(([1, 2, 3], None))
    cases.append((dict(g.propose_req("m9", ds), evaluationId=""), None))
    for body, raw in cases:
        r = post(c, body, raw)
        assert r.status_code in (400, 422), (r.status_code, r.text, body if raw is None else raw)
    assert fake.calls == 0


if __name__ == "__main__":
    test_full_flow()
    test_malformed_never_calls_model()
    print("ALL TESTS PASSED")
