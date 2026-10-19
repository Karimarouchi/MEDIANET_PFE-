"""
Prints the Woodpecker API token Vulnix uses to drive Woodpecker, without opening the Woodpecker UI.

Same token as "User settings > CLI & API" in Woodpecker: a HS256 JWT {"type": "user", "user-id": <id>}
signed with the user's hash (shared/token in Woodpecker). Never opens the live database: Woodpecker keeps it in
WAL mode and a second process on a Docker bind mount breaks its locks ("disk I/O error"). It reads a temporary copy.

Run it after the admin logged in to Woodpecker once (this creates the user):
  local   : python vulnix-token.py
  server  : docker run --rm -e WOODPECKER_ADMIN="$(grep ^WOODPECKER_ADMIN= .env | cut -d= -f2)" -v "$PWD/data:/data:ro" -v "$PWD/vulnix-token.py:/t.py:ro" python:3.12-alpine python -I /t.py /data/woodpecker.sqlite
Put the printed value in Vulnix (vulnix.ci.woodpecker-token). Never commit it.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import sys
import tempfile


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    db = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "data", "woodpecker.sqlite")
    admin = os.environ.get("WOODPECKER_ADMIN") or read_env(os.path.join(here, ".env")).get("WOODPECKER_ADMIN", "")
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "woodpecker.sqlite")
        shutil.copyfile(db, copy)
        if os.path.exists(db + "-wal"):
            shutil.copyfile(db + "-wal", copy + "-wal")
        con = sqlite3.connect(copy)
        row = con.execute("select id, hash from users where login = ? and admin = 1", (admin,)).fetchone()
        con.close()
    if not row:
        print(f"Aucun admin '{admin}' dans Woodpecker : connecte-toi une fois sur Woodpecker avec ce compte GitHub.",
              file=sys.stderr)
        return 1
    user_id, user_hash = row
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64(json.dumps({"type": "user", "user-id": str(user_id)}, separators=(",", ":")).encode())
    sig = hmac.new(user_hash.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
    print(f"{header}.{claims}.{b64(sig)}")
    return 0


def read_env(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


if __name__ == "__main__":
    sys.exit(main())
