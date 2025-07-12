#!/usr/bin/env sh
set -eu

echo "[entrypoint] 🚀 Starting PUM container…"

# ───────── 1) Create or reuse the chosen UID/GID ──────────
DEFAULT_UID='1000'
DEFAULT_GID='1000'
PUID="${PUID:-$DEFAULT_UID}"
PGID="${PGID:-$DEFAULT_GID}"

# Only attempt user/group changes if running as root
if [ "$(id -u)" = "0" ]; then
  echo "[entrypoint] 👤 Wanted UID=$PUID GID=$PGID"

  # Figure out which *names* already map to those numeric IDs
  EXISTING_USER="$(getent passwd "$PUID" | cut -d: -f1 || true)"
  EXISTING_GRP="$(getent group "$PGID" | cut -d: -f1 || true)"

  # Decide what account we'll run as
  TARGET_USER="${EXISTING_USER:-pumuser}"
  TARGET_GRP="${EXISTING_GRP:-pumgroup}"

  # Create group only if the GID isn't taken
  if [ -z "$EXISTING_GRP" ]; then
    echo "[entrypoint] Creating group '$TARGET_GRP' (GID: $PGID)"
    addgroup -S -g "$PGID" "$TARGET_GRP"
  else
    echo "[entrypoint] Group GID $PGID already exists as '$EXISTING_GRP'."
    # If the name is different but GID matches, ensure the name is what we expect
    if [ "$EXISTING_GRP" != "$TARGET_GRP" ]; then
      groupmod -o -n "$TARGET_GRP" "$EXISTING_GRP" || true
      echo "[entrypoint] Renamed group from '$EXISTING_GRP' to '$TARGET_GRP'."
    fi
  fi

  # Create user only if the UID isn't taken
  if [ -z "$EXISTING_USER" ]; then
    echo "[entrypoint] Creating user '$TARGET_USER' (UID: $PUID) in group '$TARGET_GRP'."
    adduser -S -G "$TARGET_GRP" -u "$PUID" "$TARGET_USER"
  else
    echo "[entrypoint] User UID $PUID already exists as '$EXISTING_USER'."
    # Make sure the existing user is in the right group
    # adduser might fail if user is already in group, hence || true
    adduser "$EXISTING_USER" "$TARGET_GRP" || true
    # If the name is different but UID matches, ensure the name is what we expect
    if [ "$EXISTING_USER" != "$TARGET_USER" ]; then
      usermod -o -l "$TARGET_USER" "$EXISTING_USER" || true
      echo "[entrypoint] Renamed user from '$EXISTING_USER' to '$TARGET_USER'."
    fi
  fi

  # ───────── Fix ownership for bind mounts ──────────
  echo "[entrypoint] ⚙️ Fixing ownership for bind mounts to $TARGET_USER:$TARGET_GRP ($PUID:$PGID)…"
  # IMPORTANT: Removed comments from this line!
  chown -R "$PUID":"$PGID" \
    /app/instance \
    /.cache \
    /tmp

  # Optional: If you copied files with --chown to 1000:1000 and the user provides different PUID/PGID
  # this section ensures existing files inside /app are re-chowned.
  if [ "$PUID:$PGID" != "$DEFAULT_UID:$DEFAULT_GID" ]; then
    echo "[entrypoint] ⚙️ Re-fixing ownership for custom UID/GID on /app..."
    find /app -type d -not -user "$PUID" \
      -exec chown "$PUID":"$PGID" {} +
    # Find files not owned by PUID and chown them
    find /app -type f -not -user "$PUID" \
      -exec chown "$PUID":"$PGID" {} +
  else
    echo "[entrypoint] ⚙️ Default UID/GID detected; assuming ownership is correct."
  fi


  # Re-exec as that user
  exec su-exec "$TARGET_USER":"$TARGET_GRP" "$0" "$@"
fi

# This part runs *after* su-exec has dropped privileges and re-executed the script
echo "[entrypoint] 👍 Running as $(id -un):$(id -gn) ($(id -u):$(id -g))"

# ─────────────────────────────────────────────────────────────────────────────
# 2) Database migrations
# ─────────────────────────────────────────────────────────────────────────────
echo "[entrypoint] 🔧 Applying Alembic migrations for PUM…"
# Ensure you are in the correct directory if 'flask' needs it, usually /app
cd /app
flask db upgrade

# ─────────────────────────────────────────────────────────────────────────────
# 3) Hand off to your CMD (e.g. gunicorn)
# ─────────────────────────────────────────────────────────────────────────────
exec "$@"