"""Strict, atomic request validation. Runs before any AI or tool work."""
import base64
import binascii
import json
import re

PROFILE = "ga5-mailroom-action-gate/v2"
ACTIONS = (
    "create_draft", "update_internal_record", "send_approved_notice",
    "request_confirmation", "quarantine_item", "no_action",
)
PARTITIONS = ("stable_core", "fresh_audit")
MAX_DOSSIERS = 500
MAX_SOURCES = 200
MAX_LINES = 2000
MAX_STR = 20000
MAX_ID = 512


class BadRequest(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


def _no_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate JSON key {k!r}")
        d[k] = v
    return d


def parse_json(raw: bytes):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BadRequest(400, "bad_encoding", "body must be UTF-8 JSON")
    try:
        return json.loads(text, object_pairs_hook=_no_dup_keys, parse_constant=_reject_constant)
    except ValueError as e:
        raise BadRequest(400, "bad_json", f"body is not valid JSON: {str(e)[:120]}")


def _req(cond, msg, status=422, code="schema_error"):
    if not cond:
        raise BadRequest(status, code, msg)


def _is_str(v, max_len=MAX_STR, allow_empty=False):
    return isinstance(v, str) and len(v) <= max_len and (allow_empty or len(v) > 0)


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64_decode_sig(s: str) -> bytes:
    if not isinstance(s, str) or not s:
        raise ValueError("missing")
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        pass
    return b64url_decode(s)


def validate_envelope(obj):
    _req(isinstance(obj, dict), "body must be a JSON object", 400, "bad_request")
    _req(obj.get("profile") == PROFILE, "unsupported or missing profile")
    op = obj.get("operation")
    _req(op in ("propose", "commit"), "operation must be 'propose' or 'commit'", 400, "bad_operation")
    _req(_is_str(obj.get("evaluationId"), MAX_ID), "evaluationId must be a non-empty string")
    return op


def validate_propose(obj):
    rv = obj.get("receiptVerifier")
    _req(isinstance(rv, dict), "receiptVerifier must be an object")
    _req(rv.get("algorithm") == "Ed25519", "receiptVerifier.algorithm must be Ed25519")
    jwk = rv.get("publicKeyJwk")
    _req(isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519",
         "publicKeyJwk must be an OKP/Ed25519 JWK")
    try:
        x = b64url_decode(jwk.get("x"))
    except Exception:
        x = b""
    _req(len(x) == 32, "publicKeyJwk.x must be a base64url 32-byte key")

    corpus = obj.get("corpus", {})
    _req(isinstance(corpus, dict), "corpus must be an object")
    for k in ("stableCount", "freshCount"):
        if k in corpus:
            _req(isinstance(corpus[k], int) and not isinstance(corpus[k], bool) and corpus[k] >= 0,
                 f"corpus.{k} must be a non-negative integer")

    aa = obj.get("allowedActions")
    _req(isinstance(aa, list) and aa and all(a in ACTIONS for a in aa) and len(set(aa)) == len(aa),
         "allowedActions must be a non-empty list of known, unique actions")

    ds = obj.get("dossiers")
    _req(isinstance(ds, list) and 0 < len(ds) <= MAX_DOSSIERS, "dossiers must be a non-empty list")
    seen = set()
    for i, d in enumerate(ds):
        where = f"dossiers[{i}]"
        _req(isinstance(d, dict), f"{where} must be an object")
        for k in ("dossierId", "partition", "receivedAt", "mailbox", "objective"):
            _req(k in d, f"{where}.{k} is required")
        _req(_is_str(d["dossierId"], MAX_ID), f"{where}.dossierId must be a non-empty string")
        _req(d["dossierId"] not in seen, f"duplicate dossierId {d['dossierId']!r}", 422, "duplicate_dossier")
        seen.add(d["dossierId"])
        _req(d["partition"] in PARTITIONS, f"{where}.partition invalid")
        _req(_is_str(d["receivedAt"], 64), f"{where}.receivedAt must be a string")
        _req(_is_str(d["mailbox"], MAX_ID), f"{where}.mailbox must be a non-empty string")
        _req(_is_str(d["objective"], MAX_STR, allow_empty=True), f"{where}.objective must be a string")
        srcs = d.get("sources")
        _req(isinstance(srcs, list) and 0 < len(srcs) <= MAX_SOURCES, f"{where}.sources must be a non-empty list")
        line_ids = set()
        src_ids = set()
        for j, s in enumerate(srcs):
            sw = f"{where}.sources[{j}]"
            _req(isinstance(s, dict), f"{sw} must be an object")
            _req(_is_str(s.get("sourceId"), MAX_ID), f"{sw}.sourceId must be a non-empty string")
            _req(s["sourceId"] not in src_ids, f"{sw}: duplicate sourceId")
            src_ids.add(s["sourceId"])
            for k in ("kind", "provenance", "title"):
                _req(_is_str(s.get(k), MAX_STR, allow_empty=True), f"{sw}.{k} must be a string")
            lines = s.get("lines")
            _req(isinstance(lines, list) and len(lines) <= MAX_LINES, f"{sw}.lines must be a list")
            for m, ln in enumerate(lines):
                lw = f"{sw}.lines[{m}]"
                _req(isinstance(ln, dict), f"{lw} must be an object")
                _req(_is_str(ln.get("lineId"), MAX_ID), f"{lw}.lineId must be a non-empty string")
                _req(isinstance(ln.get("text"), str) and len(ln["text"]) <= MAX_STR, f"{lw}.text must be a string")
                _req(ln["lineId"] not in line_ids, f"{lw}: duplicate lineId {ln['lineId']!r}")
                line_ids.add(ln["lineId"])
        _req(len(line_ids) > 0, f"{where} has no lines")


RECEIPT_REQUIRED = ("dossierId", "callId", "action", "accepted", "proposalDigest", "receiptId", "receiptSignature")


def validate_commit(obj):
    _req(isinstance(obj.get("inputDigest"), str) and re.fullmatch(r"[0-9a-f]{64}", obj["inputDigest"]),
         "inputDigest must be lowercase SHA-256 hex")
    rs = obj.get("receipts")
    _req(isinstance(rs, list) and 0 < len(rs) <= MAX_DOSSIERS, "receipts must be a non-empty list")
    for i, r in enumerate(rs):
        w = f"receipts[{i}]"
        _req(isinstance(r, dict), f"{w} must be an object")
        for k in RECEIPT_REQUIRED:
            _req(k in r, f"{w}.{k} is required")
        for k in ("dossierId", "callId", "action", "proposalDigest", "receiptId"):
            _req(_is_str(r[k], MAX_ID), f"{w}.{k} must be a non-empty string")
        _req(isinstance(r["accepted"], bool), f"{w}.accepted must be a boolean")
        _req(_is_str(r["receiptSignature"], 4096), f"{w}.receiptSignature must be a non-empty string")
        _req(r["action"] in ACTIONS, f"{w}.action is not a known action")
