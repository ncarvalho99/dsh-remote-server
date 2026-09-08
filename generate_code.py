"""Generate a host pairing code for DSH Remote Server."""

import os
import secrets
import string
import sys
import time
from pathlib import Path

from app import db, init_db, token_hash


def generate_code() -> str:
    """Generate an 8-character pairing code like ABCD-EFGH."""
    alphabet = string.ascii_uppercase + string.digits
    # Remove ambiguous characters
    for char in ['O', '0', 'I', '1']:
        alphabet = alphabet.replace(char, '')
    part1 = ''.join(secrets.choice(alphabet) for _ in range(4))
    part2 = ''.join(secrets.choice(alphabet) for _ in range(4))
    return f"{part1}-{part2}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m generate_code <email>", file=sys.stderr)
        sys.exit(1)
    
    email = sys.argv[1].strip().lower()
    init_db()
    
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            print(f"Error: User {email} not found.", file=sys.stderr)
            sys.exit(1)
        
        # Create the codes table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_registration_codes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              code_hash TEXT UNIQUE NOT NULL,
              owner_account TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','consumed','revoked')),
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              consumed_at INTEGER,
              consumed_device_id TEXT
            )
        """)
        
        # Generate unique code
        code = generate_code()
        code_hash = token_hash(code)
        now = int(time.time() * 1000)
        expires_at = now + (10 * 60 * 1000)  # 10 minutes
        
        # Revoke any existing active codes for this account
        conn.execute(
            "UPDATE host_registration_codes SET status='revoked' WHERE owner_account=? AND status='active'",
            (email,)
        )
        
        # Insert new code
        conn.execute(
            """INSERT INTO host_registration_codes(code_hash, owner_account, status, created_at, expires_at)
               VALUES(?, ?, 'active', ?, ?)""",
            (code_hash, email, now, expires_at)
        )
        conn.commit()
    
    print(f"Pairing code for {email}: {code}")
    print(f"Valid for 10 minutes.")


if __name__ == "__main__":
    main()
