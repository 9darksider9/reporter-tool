import click
from flask.cli import with_appcontext
from .models import User, UserRole, db

def create_default_admin():
    """Create a default admin user if no users exist."""
    try:
        # Check if any users exist
        user_count = User.query.count()
        print(f"Current user count: {user_count}")  # Debug log
        
        if user_count == 0:
            print("No users found, creating default admin...")  # Debug log
            default_admin = User(
                username="admin",
                email="admin@localhost",
                role=UserRole.ADMIN.value,
                is_active=True
            )
            default_admin.set_password("admin123")
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin created successfully!")  # Debug log
            print('Username: admin')
            print('Password: admin123')
        else:
            print(f"Users already exist, skipping default admin creation")  # Debug log
    except Exception as e:
        print(f'Error creating default admin: {str(e)}')

@click.command('create-admin')
@click.argument('username')
@click.argument('email')
@click.argument('password')
@with_appcontext
def create_admin(username, email, password):
    """Create an admin user."""
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            click.echo('User already exists')
            return

        admin = User(
            username=username,
            email=email,
            role=UserRole.ADMIN.value,
            is_active=True
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        click.echo(f'Admin user {username} created successfully')
    except Exception as e:
        click.echo(f'Error creating admin user: {str(e)}')

@click.command('list-users')
@with_appcontext
def list_users():
    """List all users in the database."""
    try:
        users = User.query.all()
        if not users:
            click.echo('No users found in database')
            return
        
        click.echo('\nUsers in database:')
        for user in users:
            click.echo(f'Username: {user.username}')
            click.echo(f'Email: {user.email}')
            click.echo(f'Role: {user.role}')
            click.echo(f'Active: {user.is_active}')
            click.echo('---')
    except Exception as e:
        click.echo(f'Error listing users: {str(e)}') 