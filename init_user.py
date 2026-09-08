"""Initialize a user account in the DSH Remote Relay SQLite database.
Usage:
  DSH_REMOTE_DB=/path/to/db.sqlite3 python -m init_user <email> <password> [--admin]
"""

import os
import sys
import time
from pathlib import Path

from argon2 import PasswordHasher

from app import db, init_db


def main():
    if len(sys.argv) < 3:
        print("Usage: python -m init_user <email> <password> [--admin]", file=sys.stderr)
        sys.exit(1)
    email = sys.argv[1].strip().lower()
    password = sys.argv[2]
    is_admin = 1 if "--admin" in sys.argv[3:] else 0
    init_db()
    hasher = PasswordHasher()
    pwd_hash = hasher.hash(password)
    now = int(time.time() * 1000)
    with db() as conn:
        conn.execute(
            """INSERT INTO users(email, password_hash, is_admin, created_at)
               VALUES(?, ?, ?, ?)
               ON CONFLICT(email) DO UPDATE SET password_hash=excluded.password_hash, is_admin=excluded.is_admin""",
            (email, pwd_hash, is_admin, now),
        )
        conn.commit()
    print(f"User {email} provisioned (admin={bool(is_admin)}).")


if __name__ == "__main__":
    main()
