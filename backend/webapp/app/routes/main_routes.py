from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return redirect(url_for('main.dashboard'))  # Redirects to dashboard

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')