#!/bin/bash

# Set the working directory to the script's location
cd "$(dirname "$0")"

# Activate the virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Virtual environment not found. Please set up the environment first."
    exit 1
fi

# Ensure necessary packages are installed
echo "Checking required packages..."
pip install flask-migrate flask-sqlalchemy

# Create logs directory if it doesn't exist
mkdir -p app/logs
touch app/logs/audit.log app/logs/authentication.log app/logs/usage.log

# Initialize migrations if not already initialized
if [ ! -f "migrations/alembic.ini" ]; then
    echo "Migrations not initialized. Running flask db init..."
    flask db init
fi

echo "Starting database migration..."

# Create new migration
echo "Creating new migration for API key changes..."
flask db migrate -m "Make user_id nullable in api_key table"

if [ $? -ne 0 ]; then
    echo "Error creating migration. Please check the error message above."
    exit 1
fi

# Apply the migration
echo "Applying migration..."
flask db upgrade

if [ $? -ne 0 ]; then
    echo "Error applying migration. Please check the error message above."
    exit 1
fi

echo "Migration completed successfully!"

# Deactivate virtual environment
deactivate

echo "Done!"