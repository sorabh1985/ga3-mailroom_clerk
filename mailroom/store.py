"""Durable key-value storage.

Production: Upstash Redis over its REST API (free tier; Vercel Marketplace sets the
env vars). Local/testing: SQLite file. Process memory is never the source of truth.
"""
import asyncio
import json
import os
import sqlite3
import time

import httpx


class StoreError(Exception):
    pass


class UpstashStore:
    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.kind = "upstash"

    def _client(self):
        # One keep-alive client per event loop: avoids a new TLS handshake for every command.
        loop = asyncio.get_running_loop()
        if getattr(self, "_loop", None) is not loop:
            self._loop = loop
            self._http = httpx.AsyncClient(timeout=8.0)
        return self._http

    async def _cmd(self, *args):
        last = None
        for attempt in range(3):
            try:
                if True:
                    c = self._client()
                    r = await c.post(self.url, headers=self.headers, json=[str(a) for a in args])
                if r.status_code == 200:
                    return r.json().get("result")
                last = f"HTTP {r.status_code}: {r.text[:200]}"
                if r.status_code < 500:
                    break
            except httpx.HTTPError as e:
                last = repr(e)
            await asyncio.sleep(0.3 * (attempt + 1))
        raise StoreError(f"upstash command failed: {last}")

    async def get(self, key):
        return await self._cmd("GET", key)

    async def mget(self, keys):
        if not keys:
            return []
        return await self._cmd("MGET", *keys)

    async def set(self, key, value, ex=None):
        args = ["SET", key, value] + (["EX", int(ex)] if ex else [])
        await self._cmd(*args)

    async def set_nx(self, key, value, ex=None):
        args = ["SET", key, value, "NX"] + (["EX", int(ex)] if ex else [])
        return (await self._cmd(*args)) == "OK"

    async def mset(self, mapping):
        if not mapping:
            return
        flat = []
        for k, v in mapping.items():
            flat += [k, v]
        await self._cmd("MSET", *flat)

    async def delete(self, key):
        await self._cmd("DEL", key)


class SqliteStore:
    def __init__(self, path: str):
        self.path = path
        self.kind = "sqlite"
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp REAL)")

    def _conn(self):
        return sqlite3.connect(self.path, timeout=10, isolation_level=None)

    def _get(self, c, key):
        row = c.execute("SELECT v, exp FROM kv WHERE k=?", (key,)).fetchone()
        if not row:
            return None
        if row[1] is not None and row[1] < time.time():
            c.execute("DELETE FROM kv WHERE k=?", (key,))
            return None
        return row[0]

    async def get(self, key):
        with self._conn() as c:
            return self._get(c, key)

    async def mget(self, keys):
        with self._conn() as c:
            return [self._get(c, k) for k in keys]

    async def set(self, key, value, ex=None):
        exp = time.time() + ex if ex else None
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO kv (k, v, exp) VALUES (?,?,?)", (key, value, exp))

    async def set_nx(self, key, value, ex=None):
        exp = time.time() + ex if ex else None
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            if self._get(c, key) is not None:
                c.execute("COMMIT")
                return False
            c.execute("INSERT OR REPLACE INTO kv (k, v, exp) VALUES (?,?,?)", (key, value, exp))
            c.execute("COMMIT")
            return True

    async def mset(self, mapping):
        with self._conn() as c:
            for k, v in mapping.items():
                c.execute("INSERT OR REPLACE INTO kv (k, v, exp) VALUES (?,?,NULL)", (k, v))

    async def delete(self, key):
        with self._conn() as c:
            c.execute("DELETE FROM kv WHERE k=?", (key,))


_store = None


def get_store():
    global _store
    if _store is None:
        url = os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL")
        token = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        if url and token:
            _store = UpstashStore(url, token)
        else:
            path = os.environ.get("SQLITE_PATH") or ("/tmp/mailroom.sqlite3" if os.environ.get("VERCEL") else "mailroom.sqlite3")
            _store = SqliteStore(path)
    return _store


def set_store(store):
    global _store
    _store = store


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
