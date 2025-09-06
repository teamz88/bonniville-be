#!/bin/bash

# Exit on any error
set -e

# Wait for database to be ready
echo "Waiting for database..."
while ! python manage.py check --database default; do
  echo "Database is unavailable - sleeping"
  sleep 1
done
echo "Database is up - continuing..."

# Create any missing migrations
echo "Creating missing migrations..."
python manage.py makemigrations --noinput

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start the application
echo "Starting application..."
exec "$@"