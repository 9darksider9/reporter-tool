from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, UserRole
from ..forms import LoginForm, RegistrationForm
from .. import db
from datetime import datetime
from werkzeug.urls import url_parse

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            current_app.audit_logger.log_auth(
                username=form.username.data,
                status='failure',
                details={'reason': 'Invalid username or password'}
            )
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))
        
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        current_app.audit_logger.log_auth(
            username=user.username,
            status='success',
            details={'user_id': user.id}
        )
        
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        current_app.audit_logger.log_auth(
            username=current_user.username,
            status='success',
            details={'action': 'logout'}
        )
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data, 
            email=form.email.data,
            role=UserRole.USER.value,  # Set default role to USER
            is_active=True
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title='Register', form=form) 