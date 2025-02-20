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

    echo "Initializing new migrations..."
    flask db init

    echo "Creating initial migration..."
    flask db migrate -m "initial migration"

    echo "Applying migration..."
    flask db upgrade

    echo "Creating admin user with all roles..."
    flask shell << EOF
from app.models import User, UserRole, db
# Create admin with all roles (USER + ANALYST + ENGINEER + ADMIN)
admin = User(
    username='admin',
    email='admin@example.com',
    roles=UserRole.USER.value | UserRole.ANALYST.value | UserRole.ENGINEER.value | UserRole.ADMIN.value
)
admin.set_password('admin')
db.session.add(admin)

# Create a test user with basic role
user = User(
    username='user',
    email='user@example.com',
    roles=UserRole.USER.value
)
user.set_password('user')
db.session.add(user)

# Create an analyst
analyst = User(
    username='analyst',
    email='analyst@example.com',
    roles=UserRole.USER.value | UserRole.ANALYST.value
)
analyst.set_password('analyst')
db.session.add(analyst)

# Create an engineer
engineer = User(
    username='engineer',
    email='engineer@example.com',
    roles=UserRole.USER.value | UserRole.ENGINEER.value
)
engineer.set_password('engineer')
db.session.add(engineer)

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