#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

# This collects all static files (like for the admin panel, if you use it)
python manage.py collectstatic --no-input