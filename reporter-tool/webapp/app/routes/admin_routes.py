from flask import Blueprint, render_template, jsonify, current_app
from flask_login import login_required
from ..decorators import admin_required
import os
from datetime import datetime, timedelta

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/')
@login_required
@admin_required
def dashboard():
    return render_template('admin/dashboard.html')

@bp.route('/logs/stats')
@login_required
@admin_required
def get_log_stats():
    """Get statistics about logs for the dashboard"""
    try:
        log_dir = os.path.join(current_app.root_path, 'logs')
        stats = {
            'audit': {'size': 0, 'last_modified': None, 'entry_count': 0},
            'authentication': {'size': 0, 'last_modified': None, 'entry_count': 0},
            'usage': {'size': 0, 'last_modified': None, 'entry_count': 0}
        }
        
        for log_type in stats:
            log_file = os.path.join(log_dir, f'{log_type}.log')
            if os.path.exists(log_file):
                stats[log_type]['size'] = os.path.getsize(log_file)
                stats[log_type]['last_modified'] = datetime.fromtimestamp(
                    os.path.getmtime(log_file)
                ).isoformat()
                with open(log_file, 'r') as f:
                    stats[log_type]['entry_count'] = sum(1 for _ in f)
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 