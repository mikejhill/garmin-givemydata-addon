#!/bin/bash
set -e

mkdir -p /data/browser_profile

echo "Starting Garmin Auth API server..."
exec python3 /app/garmin_auth_api.py
