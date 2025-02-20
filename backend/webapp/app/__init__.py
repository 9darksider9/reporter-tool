from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from .config import Config
import json
from flask_wtf.csrf import generate_csrf
from .utils.logger import AuditLogger

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = 'auth.login'

    # Initialize logging
    audit_logger = AuditLogger(app)
    app.audit_logger = audit_logger

    # Add CSRF token to all JSON responses
    @app.after_request
    def add_csrf_token(response):
        if response.content_type == 'application/json':
            try:
                data = json.loads(response.get_data(as_text=True))
                if isinstance(data, dict):
                    data['csrf_token'] = generate_csrf()
                    response.set_data(json.dumps(data))
            except:
                pass
        return response

    # Import and register blueprints
    from .routes.main_routes import bp as main_bp
    from .routes.auth_routes import bp as auth_bp
    from .routes.config_routes import bp as config_bp
    from .routes.api import bp as api_bp
    from .routes.user_routes import bp as users_bp
    from .routes.log_routes import bp as log_bp
    from .routes.admin_routes import bp as admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(users_bp, url_prefix='/users')
    app.register_blueprint(log_bp)
    app.register_blueprint(admin_bp)

    # Register error handlers
    register_error_handlers(app)

    # Register CLI commands
    from .cli import create_admin, create_default_admin, list_users
    app.cli.add_command(create_admin)
    app.cli.add_command(list_users)

    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    with app.app_context():
        db.create_all()
        create_default_admin()  # Create default admin if no users exist

    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500 