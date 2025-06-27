#!/bin/bash

echo "🚀 Başlatılıyor: Django projeni güncelliyorum..."

cd /home/uni_yillik || exit

echo "📥 Git pull çalıştırılıyor..."
git pull origin main

echo "🐍 Virtual environment etkinleştiriliyor..."
source venv/bin/activate

echo "📦 Statik dosyalar toplanıyor (collectstatic)..."
python manage.py collectstatic --noinput

echo "🔁 Gunicorn yeniden başlatılıyor..."
systemctl restart gunicorn

echo "✅ Deploy tamamlandı."
