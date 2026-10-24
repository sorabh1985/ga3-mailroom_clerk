"""Canonical JSON and hashing.

Canonical form = recursively key-sorted, compact JSON, UTF-8, non-ASCII kept as-is
(same as JavaScript JSON.stringify with sorted keys). Arrays keep their order.
"""
import hashlib
import json


def _norm(o):
    if isinstance(o, dict):
        return {k: _norm(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_norm(v) for v in o]
    if isinstance(o, float) and o.is_integer() and abs(o) < 1e21:
        # JavaScript prints 1.0 as 1
        return int(o)
    return o


def canonical(obj) -> bytes:
    return json.dumps(
        _norm(obj), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    return sha256_hex(canonical(obj))


def input_digest(dossiers) -> str:
    return digest(dossiers)


def proposal_digest(p: dict) -> str:
    view = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p.get("target"),
        "payload": p["payload"],
        "evidence": sorted(p["evidence"]),
    }
    return digest(view)


def dossier_fingerprint(dossier: dict) -> str:
    return digest(dossier)


def call_id_for(dossier_id: str, fingerprint: str) -> str:
    # Stable across evaluations; 43 chars from the allowed alphabet.
    return "mr." + sha256_hex((dossier_id + "\x00" + fingerprint).encode("utf-8"))[:40]
