from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import os
from flask import request, has_request_context, current_app
from functools import wraps

class AuditLogger:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        try:
            # Ensure log directory exists
            log_dir = os.path.join(app.root_path, 'logs')
            os.makedirs(log_dir, exist_ok=True)
            print(f"[DEBUG] Log directory created/verified at: {log_dir}")

            # Create empty log files if they don't exist
            for log_type in ['audit', 'authentication', 'usage']:
                log_file = os.path.join(log_dir, f'{log_type}.log')
                if not os.path.exists(log_file):
                    print(f"[DEBUG] Creating new log file: {log_file}")
                    with open(log_file, 'w') as f:
                        f.write('')  # Create empty file
                else:
                    print(f"[DEBUG] Existing log file found: {log_file}")

                # Verify file permissions
                if not os.access(log_file, os.W_OK):
                    print(f"[WARNING] No write permission for {log_file}")
                    os.chmod(log_file, 0o666)  # Make file writable

            print("[DEBUG] Logger initialization complete")

        except Exception as e:
            print(f"[ERROR] Error initializing logger: {str(e)}")
            raise

    def _get_request_info(self):
        if not has_request_context():
            return {
                'access_type': 'console',
                'ip_address': None,
                'user_agent': None
            }
        
        return {
            'access_type': 'api' if request.headers.get('X-Requested-With') == 'XMLHttpRequest' else 'web',
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string
        }

    def _write_log(self, log_type, log_entry):
        try:
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            log_line = f"{timestamp} {json.dumps(log_entry)}\n"
            
            log_file = os.path.join(current_app.root_path, 'logs', f'{log_type}.log')
            with open(log_file, 'a') as f:
                f.write(log_line)
            
            print(f"[DEBUG] Wrote {log_type} log: {log_line.strip()}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to write {log_type} log: {str(e)}")
            return False

    def log_auth(self, username, status, details=None):
        try:
            request_info = self._get_request_info()
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'username': username,
                'status': status,
                'access_type': request_info['access_type'],
                'ip_address': request_info['ip_address'],
                'user_agent': request_info['user_agent']
            }
            if details:
                log_entry['details'] = details

            return self._write_log('authentication', log_entry)
        except Exception as e:
            print(f"[ERROR] Failed to create authentication log entry: {str(e)}")
            return False

    def log_audit(self, actor, action, status, details=None):
        try:
            request_info = self._get_request_info()
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'actor': actor,
                'action': action,
                'status': status,
                'access_type': request_info['access_type'],
                'ip_address': request_info['ip_address'],
                'user_agent': request_info['user_agent']
            }
            if details:
                log_entry['details'] = details

            return self._write_log('audit', log_entry)
        except Exception as e:
            print(f"[ERROR] Failed to create audit log entry: {str(e)}")
            return False

    def log_usage(self, user, action, details=None):
        try:
            request_info = self._get_request_info()
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'user': user,
                'action': action,
                'access_type': request_info['access_type'],
                'ip_address': request_info['ip_address'],
                'user_agent': request_info['user_agent']
            }
            if details:
                log_entry['details'] = details

            return self._write_log('usage', log_entry)
        except Exception as e:
            print(f"[ERROR] Failed to create usage log entry: {str(e)}")
            return False

def audit_log(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            
            try:
                result = f(*args, **kwargs)
                status = 'success'
            except Exception as e:
                status = 'failure'
                raise e
            finally:
                if hasattr(current_app, 'audit_logger'):
                    current_app.audit_logger.log_audit(
                        actor=current_user.username if not current_user.is_anonymous else 'anonymous',
                        action=action,
                        status=status
                    )
            return result
        return decorated_function
    return decorator

def usage_log(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            
            result = f(*args, **kwargs)
            
            if hasattr(current_app, 'audit_logger'):
                current_app.audit_logger.log_usage(
                    user=current_user.username if not current_user.is_anonymous else 'anonymous',
                    action=action
                )
            return result
        return decorated_function
    return decorator 