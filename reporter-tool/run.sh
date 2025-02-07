#!/bin/bash

# Activate virtual environment if it exists, create it if it doesn't
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip3
pip3 install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip3 install -e .

# Set Flask environment variables
export FLASK_APP=webapp/run.py
export FLASK_ENV=development
export FLASK_DEBUG=1
export FLASK_RUN_PORT=13500

# Create instance directory if it doesn't exist
mkdir -p webapp/instance
chmod 755 webapp/instance

# Initialize the database
echo "Initializing database..."
cd webapp
export PYTHONPATH=$PYTHONPATH:$(pwd)
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# Run the application
echo "Starting the application..."
python3 run.py 