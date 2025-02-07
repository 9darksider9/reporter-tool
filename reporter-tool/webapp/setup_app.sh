#!/bin/bash

echo "Reporter Tool Setup Script"
echo "========================="
echo "This script will:"
echo "1. Reset the database"
echo "2. Create initial migrations"
echo "3. Create an admin account"
echo ""
echo "Warning: This will delete all existing data!"
echo "Are you sure you want to continue? (y/n)"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]
then
    echo "Setting up Flask environment..."
    export FLASK_APP=run.py
    export PYTHONPATH=$PYTHONPATH:$(pwd)

    echo "Removing existing database and migrations..."
    rm -rf migrations
    rm -f instance/app.db

    echo "Initializing new database..."
    flask db init

    echo "Creating initial migration..."
    flask db migrate -m "initial migration"

    echo "Applying migration..."
    flask db upgrade

    echo "Creating admin account..."
    echo "------------------------"
    echo "Default credentials will be:"
    echo "Username: admin"
    echo "Email: admin@localhost"
    echo "Password: admin123"
    echo ""
    echo "Would you like to use these default credentials? (y/n)"
    read -r use_default

    if [[ "$use_default" =~ ^([yY][eE][sS]|[yY])+$ ]]
    then
        flask create-admin admin admin@localhost admin123
    else
        echo "Please enter admin account details:"
        echo -n "Username: "
        read -r admin_username
        echo -n "Email: "
        read -r admin_email
        echo -n "Password: "
        read -rs admin_password
        echo ""

        flask create-admin "$admin_username" "$admin_email" "$admin_password"
    fi

    echo "Verifying setup..."
    flask list-users

    echo "Setup complete!"
    echo "You can now start the application"
else
    echo "Setup cancelled."
fi 