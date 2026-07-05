#!/usr/bin/env bash
# Render.com build script
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input

# Veritabanı komutları — bağlantı hatası olursa build çökmesin
python manage.py migrate || echo "⚠️ WARNING: migrate failed (database may be unavailable)"
python manage.py seed_data || echo "⚠️ WARNING: seed_data failed (database may be unavailable)"
