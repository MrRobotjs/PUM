#!/bin/sh
set -e # Exit immediately if a command exits with a non-zero status.

echo "Running database migrations..."
flask db upgrade

echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 --forwarded-allow-ips "*" run:app