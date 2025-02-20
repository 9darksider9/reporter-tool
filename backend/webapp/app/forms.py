from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, SubmitField, IntegerField, BooleanField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, NumberRange, Optional, URL
from .models import User, UserRole

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class StorageConfigForm(FlaskForm):
    name = StringField('Configuration Name', validators=[DataRequired()])
    storage_type = SelectField('Storage Type', choices=[('aws', 'AWS S3'), ('azure', 'Azure Blob Storage')])
    
    # AWS Fields
    aws_access_key = StringField('AWS Access Key')
    aws_secret_key = StringField('AWS Secret Key')
    aws_bucket_name = StringField('S3 Bucket Name')
    aws_region = StringField('AWS Region')

    # Azure Fields
    azure_connection_string = TextAreaField('Azure Connection String')
    azure_container_name = StringField('Container Name')

    submit = SubmitField('Save Configuration')

class LoggingConfigForm(FlaskForm):
    log_level = SelectField('Log Level', 
                          choices=[('DEBUG', 'Debug'), 
                                 ('INFO', 'Info'),
                                 ('WARNING', 'Warning'),
                                 ('ERROR', 'Error'),
                                 ('CRITICAL', 'Critical')])
    
    log_destination = SelectField('Log Destination',
                                choices=[('file', 'Local File'),
                                        ('cloudwatch', 'AWS CloudWatch'),
                                        ('azure_monitor', 'Azure Monitor')])
    
    file_path = StringField('Log File Path')
    cloudwatch_group = StringField('CloudWatch Log Group')
    cloudwatch_stream = StringField('CloudWatch Stream Name')
    azure_workspace_id = StringField('Azure Workspace ID')
    azure_primary_key = StringField('Azure Primary Key')
    log_retention_days = IntegerField('Log Retention (Days)', 
                                    validators=[NumberRange(min=1, max=365)],
                                    default=30)
    enabled = BooleanField('Enable Logging')
    submit = SubmitField('Save Logging Configuration')

class APIKeyForm(FlaskForm):
    key_name = StringField('Key Name', validators=[
        DataRequired(),
        Length(min=1, max=64)
    ])
    submit = SubmitField('Generate API Key')

class ScannerConfigForm(FlaskForm):
    name = StringField('Scanner Name', validators=[
        DataRequired(),
        Length(min=1, max=64)
    ])
    scanner_type = SelectField('Scanner Type', choices=[
        ('url', 'URL Scanner'),
        ('ip', 'IP Scanner')
    ])
    base_url = StringField('Base URL', validators=[
        DataRequired(),
        URL()
    ])
    endpoint = StringField('API Endpoint', validators=[DataRequired()])
    http_method = SelectField('HTTP Method', choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE')
    ])
    headers = TextAreaField('Headers (JSON)', validators=[Optional()])
    query_params = TextAreaField('Query Parameters (JSON)', validators=[Optional()])
    body_template = TextAreaField('Request Body Template (JSON)', validators=[Optional()])
    response_mapping = TextAreaField('Response Mapping (JSON)', validators=[Optional()])
    enabled = BooleanField('Enable Scanner')
    submit = SubmitField('Save Scanner')

class IntegrationForm(FlaskForm):
    class Meta:
        csrf = True

    name = StringField('Integration Name', validators=[DataRequired()])
    http_method = SelectField('HTTP Method', choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE')
    ], validators=[DataRequired()])
    base_url = StringField('Base URL', validators=[
        DataRequired(),
        URL(require_tld=False, message='Please enter a valid URL (e.g., https://api.example.com)')
    ])
    endpoint = StringField('API Endpoint', validators=[DataRequired()])
    api_key_name = StringField('API Key Name', validators=[DataRequired()])
    api_secret = PasswordField('API Secret', validators=[Optional()])
    submit = SubmitField('Save Integration')

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    roles = MultiCheckboxField('Roles', coerce=int, choices=[
        (UserRole.USER.value, 'User'),
        (UserRole.ANALYST.value, 'Analyst'),
        (UserRole.ENGINEER.value, 'Engineer'),
        (UserRole.ADMIN.value, 'Admin')
    ])
    submit = SubmitField('Save User')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if kwargs.get('is_edit'):
            self.password.validators = [Optional()]
        else:
            self.password.validators = [DataRequired(), Length(min=8)] 