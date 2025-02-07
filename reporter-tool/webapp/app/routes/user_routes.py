from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from ..models import User, UserRole, db, APIKey
from ..forms import UserForm, APIKeyForm
from ..decorators import admin_required
from ..utils.logger import audit_log

bp = Blueprint('users', __name__)

@bp.route('/')
@login_required
@admin_required
def users():
    user_form = UserForm()
    users = User.query.all()
    return render_template('users/index.html', users=users, form=user_form, UserRole=UserRole)

@bp.route('/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'roles': user.roles,
            'role_names': user.role_names,
            'is_active': user.is_active
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/create', methods=['POST'])
@login_required
@admin_required
@audit_log('create_user')
def create_user():
    try:
        print("\n=== Starting User Creation ===")
        if not request.is_json:
            print("Error: Request is not JSON")
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
            
        data = request.get_json()
        print("Request Data:", data)
        
        # Skip CSRF validation for API requests
        form = UserForm(meta={'csrf': False})
        form.username.data = data.get('username')
        form.email.data = data.get('email')
        form.password.data = data.get('password')
        
        # Handle roles properly - convert to list of integers
        roles_data = data.get('roles', [])
        if isinstance(roles_data, str):
            roles_data = [int(roles_data)] if roles_data else []
        elif isinstance(roles_data, list):
            roles_data = [int(role) for role in roles_data if role]
        
        form.roles.data = roles_data

        if not form.validate():
            print("Validation Errors:", form.errors)
            return jsonify({
                'status': 'error',
                'message': 'Validation failed',
                'errors': {field: errors for field, errors in form.errors.items()}
            }), 400

        # Calculate combined roles value
        combined_roles = sum(int(role) for role in roles_data)
        if combined_roles == 0:
            combined_roles = UserRole.USER.value  # Default to USER role if none selected

        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            return jsonify({
                'status': 'error',
                'message': 'Validation failed',
                'errors': {'username': ['Username already exists']}
            }), 400
            
        if User.query.filter_by(email=form.email.data).first():
            return jsonify({
                'status': 'error',
                'message': 'Validation failed',
                'errors': {'email': ['Email already exists']}
            }), 400

        user = User(
            username=form.username.data,
            email=form.email.data,
            roles=combined_roles,
            is_active=True
        )
        user.set_password(form.password.data)
        
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='create_user',
            status='success',
            details={
                'created_user': user.username,
                'roles': user.role_names,
                'email': user.email
            }
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'User created successfully'
        })
            
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='create_user',
            status='failure',
            details={'error': str(e)}
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    try:
        print("\n=== Starting User Update ===")
        if not request.is_json:
            print("Error: Request is not JSON")
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
            
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        print("Request Data:", data)
        print("Headers:", dict(request.headers))
        
        # Create form with is_edit=True to make password optional
        form = UserForm(meta={'csrf': False}, is_edit=True)
        
        # Validate without password if not provided
        if not data.get('password'):
            form.password.validators = []
        
        form.username.data = data.get('username', user.username)
        form.email.data = data.get('email', user.email)
        form.roles.data = data.get('roles', user.roles)

        if not form.validate():
            print("Validation Errors:", form.errors)
            return jsonify({
                'status': 'error',
                'message': 'Validation failed',
                'errors': form.errors
            }), 400

        # Store old values for logging
        old_values = {
            'username': user.username,
            'email': user.email,
            'roles': user.role_names
        }
        
        # Update user fields
        user.username = form.username.data
        user.email = form.email.data
        user.roles = sum(int(role) for role in form.roles.data)
        
        if data.get('password'):
            user.set_password(data['password'])
        
        db.session.commit()
        
        # Log the user update
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='update_user',
            status='success',
            details={
                'user_id': user.id,
                'changes': {
                    field: {'old': old_values[field], 'new': getattr(user, field) if field != 'roles' else user.role_names}
                    for field in old_values
                    if old_values[field] != (getattr(user, field) if field != 'roles' else user.role_names)
                }
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': 'User updated successfully'
        })
            
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='update_user',
            status='failure',
            details={
                'user_id': user_id,
                'error': str(e)
            }
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({
            'status': 'error',
            'message': 'Cannot delete your own account'
        }), 400
        
    try:
        user = User.query.get_or_404(user_id)
        user_info = {
            'username': user.username,
            'email': user.email,
            'roles': user.role_names
        }
        
        db.session.delete(user)
        db.session.commit()
        
        # Log the user deletion
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_user',
            status='success',
            details=user_info
        )
        
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_user',
            status='failure',
            details={
                'user_id': user_id,
                'error': str(e)
            }
        )
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/<int:user_id>/api-keys', methods=['GET'])
@login_required
def user_api_keys(user_id):
    try:
        # Only admins can view other users' API keys
        if not current_user.is_admin and current_user.id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get_or_404(user_id)
        api_keys = APIKey.query.filter_by(user_id=user_id).order_by(APIKey.created_at.desc()).all()
        
        return jsonify({
            'api_keys': [{
                'id': key.id,
                'key_name': key.key_name,
                'created_at': key.created_at.isoformat(),
                'last_used': key.last_used.isoformat() if key.last_used else None,
                'enabled': key.enabled
            } for key in api_keys]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/<int:user_id>/api-keys', methods=['POST'])
@login_required
def create_user_api_key(user_id):
    # Only admins can create API keys for other users
    if not current_user.is_admin and current_user.id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        form = APIKeyForm()
        if form.validate_on_submit():
            api_key = APIKey.generate_key()
            key = APIKey(
                user_id=user_id,
                key_name=form.key_name.data
            )
            key.set_key(api_key)
            db.session.add(key)
            db.session.commit()
            
            # Log API key creation
            current_app.audit_logger.log_audit(
                actor=current_user.username,
                action='create_api_key',
                status='success',
                details={
                    'key_name': key.key_name,
                    'user_id': user_id,
                    'key_id': key.id
                }
            )
            
            return jsonify({
                'status': 'success',
                'message': 'API key created successfully',
                'key': api_key
            })
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='create_api_key',
            status='failure',
            details={
                'user_id': user_id,
                'error': str(e)
            }
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/api-keys/<int:key_id>/toggle', methods=['POST'])
@login_required
def toggle_api_key(key_id):
    try:
        key = APIKey.query.get_or_404(key_id)
        
        # Allow admins to toggle any key, including system keys (where user_id is None)
        if not current_user.is_admin and key.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        key.enabled = not key.enabled
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    try:
        key = APIKey.query.get_or_404(key_id)
        
        # Allow admins to delete any key, including system keys (where user_id is None)
        if not current_user.is_admin and key.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        key_info = {
            'key_id': key.id,
            'key_name': key.key_name,
            'user_id': key.user_id,
            'is_system_key': key.user_id is None
        }
        
        db.session.delete(key)
        db.session.commit()
        
        # Log API key deletion
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_api_key',
            status='success',
            details=key_info
        )
        
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_api_key',
            status='failure',
            details={
                'key_id': key_id,
                'error': str(e)
            }
        )
        return jsonify({'error': str(e)}), 500

@bp.route('/system-api-keys', methods=['GET'])
@login_required
@admin_required
def system_api_keys():
    try:
        api_keys = APIKey.query.filter_by(user_id=None).order_by(APIKey.created_at.desc()).all()
        return jsonify({
            'api_keys': [{
                'id': key.id,
                'key_name': key.key_name,
                'created_at': key.created_at.isoformat(),
                'last_used': key.last_used.isoformat() if key.last_used else None,
                'enabled': key.enabled
            } for key in api_keys]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/system-api-keys', methods=['POST'])
@login_required
@admin_required
def create_system_api_key():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        key_name = data.get('key_name')
        
        if not key_name:
            return jsonify({'error': 'Key name is required'}), 400
            
        api_key = APIKey.generate_key()
        key = APIKey(
            user_id=None,  # System key not tied to any user
            key_name=key_name
        )
        key.set_key(api_key)
        db.session.add(key)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'System API key created successfully',
            'key': api_key
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 