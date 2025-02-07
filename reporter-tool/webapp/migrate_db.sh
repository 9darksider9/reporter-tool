#!/bin/bash

# Set the working directory to the script's location
cd "$(dirname "$0")"

# Activate the virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "Virtual environment not found. Please run setup_app.sh first."
    exit 1
fi

# Check and install required packages
echo "Checking required packages..."
pip install flask-migrate flask-sqlalchemy

# Initialize migrations if not already initialized
if [ ! -d "migrations" ]; then
    echo "Initializing migrations..."
    flask db init
    
    if [ $? -ne 0 ]; then
        echo "Error initializing migrations. Please check the error message above."
        exit 1
    fi
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