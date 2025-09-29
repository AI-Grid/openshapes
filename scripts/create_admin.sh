#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: scripts/create_admin.sh <username> <password> [discord_id]" >&2
  exit 1
fi

export CREATE_ADMIN_USERNAME="$1"
export CREATE_ADMIN_PASSWORD="$2"
export CREATE_ADMIN_DISCORD_ID="${3:-}"

python - <<'PY'
import os

from werkzeug.security import generate_password_hash

from server.app import create_app
from server.models import User
from server.utils import generate_api_key

username = os.environ["CREATE_ADMIN_USERNAME"]
password = os.environ["CREATE_ADMIN_PASSWORD"]
discord_id = os.environ.get("CREATE_ADMIN_DISCORD_ID") or None

app = create_app()
session = app.session_factory()
try:
    existing = session.query(User).filter_by(username=username).one_or_none()
    if existing:
        print("User already exists", flush=True)
    else:
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            api_key=generate_api_key(),
            is_superadmin=True,
            is_active=True,
            discord_id=discord_id,
        )
        session.add(user)
        session.commit()
        print(f"Created admin user '{username}'", flush=True)
finally:
    session.close()
PY
