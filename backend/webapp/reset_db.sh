#!/bin/bash

echo "Warning: This will delete all existing migrations and database data."
echo "Are you sure you want to continue? (y/n)"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]
then
    echo "Removing existing migrations and database..."
    rm -rf migrations
    rm -f instance/app.db

    echo "Setting up Flask environment..."
    export FLASK_APP=run.py
    export PYTHONPATH=$PYTHONPATH:$(pwd)

    # Reinitialize migrations if needed
    if [ ! -d "migrations" ]; then
        echo "Initializing migrations..."
        flask db init
    fi

    echo "Creating initial migration..."
    flask db migrate -m "initial migration"

    echo "Applying migration..."
    flask db upgrade

    echo "Creating admin user with all roles..."
    flask shell << EOF
from app.models import User, UserRole, db

def create_user(username, email, password, role_value):
    user = User(
        username=username,
        email=email,
        roles=role_value
    )
    user.set_password(password)
    db.session.add(user)

db.session.commit()

create_user('admin', 'admin@example.com', 'admin', 
    UserRole.USER.value | UserRole.ANALYST.value | UserRole.ENGINEER.value | UserRole.ADMIN.value)

create_user('user', 'user@example.com', 'user', UserRole.USER.value)
create_user('analyst', 'analyst@example.com', 'analyst', UserRole.USER.value | UserRole.ANALYST.value)
create_user('engineer', 'engineer@example.com', 'engineer', UserRole.USER.value | UserRole.ENGINEER.value)

db.session.commit()

print("Database initialized with test users:")
print(" - admin:admin (all roles)")
print(" - user:user (basic user)")
print(" - analyst:analyst (analyst + user)")
print(" - engineer:engineer (engineer + user)")
EOF

    echo "Database reset complete!"
else
    echo "Database reset cancelled."
fi 