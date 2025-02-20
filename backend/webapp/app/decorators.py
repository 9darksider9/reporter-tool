from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user
from .models import UserRole

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not any(current_user.has_role(role) for role in roles):
                flash('You do not have permission to access this resource.', 'danger')
                return redirect(url_for('main.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Convenience decorators for common role checks
def analyst_required(f):
    return role_required(UserRole.ANALYST, UserRole.ADMIN)(f)

def engineer_required(f):
    return role_required(UserRole.ENGINEER, UserRole.ADMIN)(f)

def admin_required(f):
    return role_required(UserRole.ADMIN)(f) 