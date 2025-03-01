from . import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
from enum import Flag, auto


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class UserRole(Flag):
    USER = auto()      # Base role - view only
    ANALYST = auto()   # Can interact with dashboard items
    ENGINEER = auto()  # Can modify configurations
    ADMIN = auto()     # Full access


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    roles = db.Column(db.Integer, nullable=False, default=UserRole.USER.value)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role):
        if isinstance(role, str):
            try:
                role = UserRole[role.upper()]
            except KeyError:
                return False
        return bool(self.roles & role.value)

    def add_role(self, role):
        self.roles |= role.value

    def remove_role(self, role):
        self.roles &= ~role.value

    @property
    def role_names(self):
        return [role.name for role in UserRole if self.has_role(role)]

    @property
    def is_admin(self):
        return self.has_role(UserRole.ADMIN)

    @property
    def is_engineer(self):
        return self.has_role(UserRole.ENGINEER)

    @property
    def is_analyst(self):
        return self.has_role(UserRole.ANALYST)

    @property
    def is_basic_user(self):
        return self.roles == UserRole.USER.value


class StorageConfig(db.Model):
    __tablename__ = 'storage_configs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    storage_type = db.Column(db.String(10), nullable=False)  # 'aws' or 'azure'
    credentials = db.Column(db.JSON, nullable=False)
    bucket_name = db.Column(db.String(64))
    container_name = db.Column(db.String(64))


class LoggingConfig(db.Model):
    __tablename__ = 'logging_configs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    log_level = db.Column(db.String(10), default='INFO')
    log_destination = db.Column(db.String(20), default='file')
    file_path = db.Column(db.String(256))
    cloudwatch_group = db.Column(db.String(256))
    cloudwatch_stream = db.Column(db.String(256))
    azure_workspace_id = db.Column(db.String(256))
    azure_primary_key = db.Column(db.String(256))
    log_retention_days = db.Column(db.Integer, default=30)
    enabled = db.Column(db.Boolean, default=True)


class APIKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    key_name = db.Column(db.String(64), nullable=False)
    key_prefix = db.Column(db.String(8), nullable=False)
    key_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean, default=True)

    @staticmethod
    def generate_key():
        return f"rt_{secrets.token_urlsafe(32)}"

    @staticmethod
    def get_prefix(api_key):
        return api_key.split('_')[1][:8]

    def set_key(self, api_key):
        self.key_prefix = self.get_prefix(api_key)
        self.key_hash = generate_password_hash(api_key)

    def check_key(self, api_key):
        if self.get_prefix(api_key) != self.key_prefix:
            return False
        return check_password_hash(self.key_hash, api_key)


class ScannerConfig(db.Model):
    __tablename__ = 'scanner_configs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    scanner_type = db.Column(db.String(10), nullable=False)
    base_url = db.Column(db.String(256), nullable=False)
    endpoint = db.Column(db.String(256), nullable=False)
    http_method = db.Column(db.String(10), nullable=False)
    headers = db.Column(db.JSON)
    query_params = db.Column(db.JSON)
    body_template = db.Column(db.JSON)
    response_mapping = db.Column(db.JSON)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    last_test = db.Column(db.DateTime)
    test_status = db.Column(db.Boolean)


class Submission(db.Model):
    __tablename__ = 'submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_malicious = db.Column(db.Boolean, default=False)
    case_number = db.Column(db.String(64))
    incident_number = db.Column(db.String(64))
    email_subject = db.Column(db.String(256))
    email_sender = db.Column(db.String(256))
    email_recipient = db.Column(db.String(256))
    email_date = db.Column(db.DateTime)
    analysis_results = db.Column(db.JSON)
    malicious_indicators = db.Column(db.JSON)
    
    user = db.relationship('User', backref='submissions', lazy=True)


class Integration(db.Model):
    __tablename__ = 'integrations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    http_method = db.Column(db.String(10), nullable=False)
    base_url = db.Column(db.String(256), nullable=False)
    endpoint = db.Column(db.String(256), nullable=False)
    api_key_name = db.Column(db.String(64), nullable=False)
    api_secret = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='integrations', lazy=True)