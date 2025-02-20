from flask import Blueprint, jsonify, request, current_app
from flask_login import current_user, login_required
from functools import wraps
from ..models import User, StorageConfig, LoggingConfig, db, APIKey, Submission, Integration
import jwt
from datetime import datetime, timedelta
from .. import config
import boto3
from azure.storage.blob import BlobServiceClient
from sqlalchemy import func
from ..decorators import admin_required
from flask_wtf.csrf import generate_csrf

bp = Blueprint('api', __name__, url_prefix='/api/v1')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer rt_'):  # API key authentication
                api_key = token.split('Bearer ')[1]
                key_prefix = APIKey.get_prefix(api_key)
                key = APIKey.query.filter_by(
                    key_prefix=key_prefix,
                    enabled=True
                ).first()
                
                if not key or not key.check_key(api_key):
                    raise ValueError('Invalid API key')
                
                key.last_used = datetime.utcnow()
                db.session.commit()
                
                current_user = User.query.get(key.user_id)
            else:  # JWT authentication
                token = token.split('Bearer ')[1]
                data = jwt.decode(token, config.Config.SECRET_KEY, algorithms=["HS256"])
                current_user = User.query.get(data['user_id'])
                
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

@bp.route('/token', methods=['POST'])
def get_token():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify'}), 401
    
    user = User.query.filter_by(username=auth.username).first()
    if not user or not user.check_password(auth.password):
        return jsonify({'message': 'Could not verify'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }, config.Config.SECRET_KEY)
    
    return jsonify({'token': token})

@bp.route('/storage', methods=['GET'])
@token_required
def get_storage_config(current_user):
    storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
    if not storage_config:
        return jsonify({'message': 'No storage configuration found'}), 404
    
    return jsonify({
        'storage_type': storage_config.storage_type,
        'bucket_name': storage_config.bucket_name,
        'container_name': storage_config.container_name
    })

@bp.route('/storage', methods=['POST'])
@token_required
def update_storage_config(current_user):
    data = request.json
    storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
    
    if not storage_config:
        storage_config = StorageConfig(user_id=current_user.id)
        db.session.add(storage_config)
    
    storage_config.storage_type = data['storage_type']
    storage_config.credentials = data['credentials']
    storage_config.bucket_name = data.get('bucket_name')
    storage_config.container_name = data.get('container_name')
    
    db.session.commit()
    return jsonify({'message': 'Storage configuration updated successfully'})

@bp.route('/logging', methods=['GET'])
@token_required
def get_logging_config(current_user):
    logging_config = LoggingConfig.query.filter_by(user_id=current_user.id).first()
    if not logging_config:
        return jsonify({'message': 'No logging configuration found'}), 404
    
    return jsonify({
        'log_level': logging_config.log_level,
        'log_destination': logging_config.log_destination,
        'file_path': logging_config.file_path,
        'cloudwatch_group': logging_config.cloudwatch_group,
        'cloudwatch_stream': logging_config.cloudwatch_stream,
        'azure_workspace_id': logging_config.azure_workspace_id,
        'log_retention_days': logging_config.log_retention_days,
        'enabled': logging_config.enabled
    })

@bp.route('/logging', methods=['POST'])
@token_required
def update_logging_config(current_user):
    data = request.json
    logging_config = LoggingConfig.query.filter_by(user_id=current_user.id).first()
    
    if not logging_config:
        logging_config = LoggingConfig(user_id=current_user.id)
        db.session.add(logging_config)
    
    logging_config.log_level = data['log_level']
    logging_config.log_destination = data['log_destination']
    logging_config.file_path = data.get('file_path')
    logging_config.cloudwatch_group = data.get('cloudwatch_group')
    logging_config.cloudwatch_stream = data.get('cloudwatch_stream')
    logging_config.azure_workspace_id = data.get('azure_workspace_id')
    logging_config.azure_primary_key = data.get('azure_primary_key')
    logging_config.log_retention_days = data.get('log_retention_days', 30)
    logging_config.enabled = data.get('enabled', True)
    
    db.session.commit()
    return jsonify({'message': 'Logging configuration updated successfully'})

@bp.route('/test-connection', methods=['POST'])
@token_required
def test_connection(current_user):
    config_type = request.json.get('type')  # 'storage' or 'logging'
    
    if config_type == 'storage':
        return validate_storage(current_user)
    elif config_type == 'logging':
        return test_logging(current_user)
    else:
        return jsonify({'message': 'Invalid configuration type'}), 400

@bp.route('/api-keys/rotate', methods=['POST'])
@token_required
def rotate_api_key(current_user):
    data = request.json
    if not data or 'key_id' not in data:
        return jsonify({'message': 'Key ID is required'}), 400
        
    old_key = APIKey.query.filter_by(
        id=data['key_id'],
        user_id=current_user.id
    ).first_or_404()
    
    # Generate new key while keeping the name
    new_api_key = APIKey.generate_key()
    new_key = APIKey(
        user_id=current_user.id,
        key_name=old_key.key_name
    )
    new_key.set_key(new_api_key)
    
    # Disable old key
    old_key.enabled = False
    
    db.session.add(new_key)
    db.session.commit()
    
    return jsonify({
        'message': 'API key rotated successfully',
        'new_key': new_api_key,
        'warning': 'Store this key safely as it won\'t be shown again'
    })

@bp.route('/analysis/<email_id>', methods=['GET'])
@token_required
def get_email_analysis(current_user, email_id):
    """Get the analysis results for a specific email"""
    try:
        # Assuming analysis results are stored in S3/Azure Blob
        storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
        if not storage_config:
            return jsonify({'message': 'Storage not configured'}), 400

        if storage_config.storage_type == 'aws':
            analysis_data = get_analysis_from_s3(storage_config, email_id)
        else:
            analysis_data = get_analysis_from_azure(storage_config, email_id)

        return jsonify(analysis_data)
    except Exception as e:
        return jsonify({'message': f'Error retrieving analysis: {str(e)}'}), 500

@bp.route('/analysis', methods=['GET'])
@token_required
def list_analyses(current_user):
    """List all available email analyses"""
    try:
        storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
        if not storage_config:
            return jsonify({'message': 'Storage not configured'}), 400

        if storage_config.storage_type == 'aws':
            analyses = list_analyses_from_s3(storage_config)
        else:
            analyses = list_analyses_from_azure(storage_config)

        return jsonify(analyses)
    except Exception as e:
        return jsonify({'message': f'Error listing analyses: {str(e)}'}), 500

def get_analysis_from_s3(storage_config, email_id):
    """Retrieve analysis results from S3"""
    try:
        session = boto3.Session(
            aws_access_key_id=storage_config.credentials['access_key'],
            aws_secret_access_key=storage_config.credentials['secret_key'],
            region_name=storage_config.credentials['region']
        )
        s3 = session.client('s3')
        
        # Get the analysis markdown file
        response = s3.get_object(
            Bucket=storage_config.bucket_name,
            Key=f'analyses/{email_id}/analysis.md'
        )
        analysis_content = response['Body'].read().decode('utf-8')
        
        # Get any associated files (reports, etc.)
        associated_files = []
        try:
            files = s3.list_objects_v2(
                Bucket=storage_config.bucket_name,
                Prefix=f'analyses/{email_id}/reports/'
            )
            if 'Contents' in files:
                associated_files = [obj['Key'] for obj in files['Contents']]
        except Exception:
            pass  # No associated files
        
        return {
            'email_id': email_id,
            'analysis': analysis_content,
            'associated_files': associated_files,
            'storage_type': 'aws',
            'bucket': storage_config.bucket_name
        }
    except Exception as e:
        raise Exception(f'Error retrieving from S3: {str(e)}')

def get_analysis_from_azure(storage_config, email_id):
    """Retrieve analysis results from Azure Blob Storage"""
    try:
        blob_service_client = BlobServiceClient.from_connection_string(
            storage_config.credentials['connection_string']
        )
        container_client = blob_service_client.get_container_client(storage_config.container_name)
        
        # Get the analysis markdown file
        blob_client = container_client.get_blob_client(f'analyses/{email_id}/analysis.md')
        analysis_content = blob_client.download_blob().readall().decode('utf-8')
        
        # Get any associated files (reports, etc.)
        associated_files = []
        try:
            files = container_client.list_blobs(name_starts_with=f'analyses/{email_id}/reports/')
            associated_files = [blob.name for blob in files]
        except Exception:
            pass  # No associated files
        
        return {
            'email_id': email_id,
            'analysis': analysis_content,
            'associated_files': associated_files,
            'storage_type': 'azure',
            'container': storage_config.container_name
        }
    except Exception as e:
        raise Exception(f'Error retrieving from Azure: {str(e)}')

def list_analyses_from_s3(storage_config):
    """List available analyses in S3"""
    session = boto3.Session(
        aws_access_key_id=storage_config.credentials['access_key'],
        aws_secret_access_key=storage_config.credentials['secret_key'],
        region_name=storage_config.credentials['region']
    )
    s3 = session.client('s3')
    
    response = s3.list_objects_v2(
        Bucket=storage_config.bucket_name,
        Prefix='analyses/',
        Delimiter='/'
    )
    
    analyses = []
    if 'CommonPrefixes' in response:
        for prefix in response['CommonPrefixes']:
            email_id = prefix['Prefix'].split('/')[1]
            analyses.append({
                'email_id': email_id,
                'url': f'/api/v1/analysis/{email_id}'
            })
    
    return {'analyses': analyses}

def list_analyses_from_azure(storage_config):
    """List available analyses in Azure Blob Storage"""
    blob_service_client = BlobServiceClient.from_connection_string(
        storage_config.credentials['connection_string']
    )
    container_client = blob_service_client.get_container_client(storage_config.container_name)
    
    blobs = container_client.list_blobs(name_starts_with='analyses/', delimiter='/')
    analyses = []
    
    # Get unique email IDs from the blob paths
    email_ids = set()
    for blob in blobs:
        parts = blob.name.split('/')
        if len(parts) > 1:
            email_ids.add(parts[1])
    
    for email_id in email_ids:
        analyses.append({
            'email_id': email_id,
            'url': f'/api/v1/analysis/{email_id}'
        })
    
    return {'analyses': analyses}

@bp.route('/api/v1/dashboard-data')
@token_required
def dashboard_data(current_user):
    days = int(request.args.get('days', 30))
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get trend data
    trend_data = db.session.query(
        func.date(Submission.submission_date).label('date'),
        func.count(Submission.id).label('count')
    ).filter(
        Submission.submission_date >= start_date,
        Submission.user_id == current_user.id
    ).group_by(
        func.date(Submission.submission_date)
    ).all()
    
    # Get malicious vs non-malicious counts
    malicious_count = Submission.query.filter(
        Submission.submission_date >= start_date,
        Submission.user_id == current_user.id,
        Submission.is_malicious == True
    ).count()
    
    total_count = Submission.query.filter(
        Submission.submission_date >= start_date,
        Submission.user_id == current_user.id
    ).count()
    
    return jsonify({
        'trend_data': {
            'labels': [str(d.date) for d in trend_data],
            'values': [d.count for d in trend_data]
        },
        'malicious_data': {
            'malicious': malicious_count,
            'non_malicious': total_count - malicious_count
        }
    })

@bp.route('/api/v1/configurations', methods=['GET'])
@token_required
def get_configurations(current_user):
    storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
    integrations = Integration.query.filter_by(user_id=current_user.id).all()
    
    return jsonify({
        'storage': {
            'id': storage_config.id if storage_config else None,
            'name': storage_config.name if storage_config else None,
            'provider': storage_config.storage_type if storage_config else None,
            'details': {
                'bucket_name': storage_config.bucket_name if storage_config and storage_config.storage_type == 'aws' else None,
                'region': storage_config.credentials.get('region') if storage_config and storage_config.storage_type == 'aws' else None,
                'container_name': storage_config.container_name if storage_config and storage_config.storage_type == 'azure' else None
            } if storage_config else None
        },
        'integrations': [{
            'id': integration.id,
            'name': integration.name,
            'base_url': integration.base_url,
            'http_method': integration.http_method,
            'endpoint': integration.endpoint
        } for integration in integrations]
    })

@bp.route('/storage-configurations', methods=['GET'])
@login_required
def get_storage_configurations():
    try:
        print("Fetching storage configurations for user:", current_user.id)
        storage_configs = StorageConfig.query.filter_by(user_id=current_user.id).all()
        print("Found configurations:", len(storage_configs))
        
        result = {
            'configurations': [{
                'id': config.id,
                'name': config.name,
                'storage_type': config.storage_type,
                'credentials': config.credentials,
                'bucket_name': config.bucket_name,
                'container_name': config.container_name
            } for config in storage_configs]
        }
        print("Returning result:", result)
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_storage_configurations: {str(e)}")
        return jsonify({
            'error': 'Failed to fetch storage configurations',
            'message': str(e)
        }), 500

@bp.route('/integrations', methods=['GET'])
@login_required
def get_integrations():
    try:
        print("DEBUG: Starting get_integrations")  # Add debug logging
        integrations = Integration.query.filter_by(user_id=current_user.id).all()
        print(f"DEBUG: Found {len(integrations)} integrations")  # Add debug logging
        
        result = {
            'integrations': [{
                'id': integration.id,
                'name': integration.name,
                'base_url': integration.base_url,
                'http_method': integration.http_method,
                'endpoint': integration.endpoint,
                'api_key_name': integration.api_key_name
            } for integration in integrations]
        }
        print(f"DEBUG: Returning result: {result}")  # Add debug logging
        return jsonify(result)
    except Exception as e:
        print(f"ERROR in get_integrations: {str(e)}")  # Add error logging
        return jsonify({
            'error': 'Failed to fetch integrations',
            'message': str(e)
        }), 500

@bp.route('/integrations', methods=['POST'])
@login_required
def create_integration():
    try:
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400

        data = request.get_json()
        integration = Integration(
            user_id=current_user.id,
            name=data.get('name'),
            http_method=data.get('http_method'),
            base_url=data.get('base_url'),
            endpoint=data.get('endpoint'),
            api_key_name=data.get('api_key_name'),
            api_secret=data.get('api_secret')
        )
        
        db.session.add(integration)
        db.session.commit()

        # Log the integration creation
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='create_integration',
            status='success',
            details={
                'integration_id': integration.id,
                'integration_name': integration.name,
                'integration_type': integration.http_method
            }
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Integration created successfully'
        })

    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='create_integration',
            status='failure',
            details={'error': str(e)}
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/integrations/<int:integration_id>', methods=['PUT'])
@login_required
def update_integration(integration_id):
    try:
        integration = Integration.query.filter_by(
            id=integration_id,
            user_id=current_user.id
        ).first_or_404()

        data = request.get_json()
        old_values = {
            'name': integration.name,
            'http_method': integration.http_method,
            'base_url': integration.base_url,
            'endpoint': integration.endpoint
        }

        # Update fields
        integration.name = data.get('name', integration.name)
        integration.http_method = data.get('http_method', integration.http_method)
        integration.base_url = data.get('base_url', integration.base_url)
        integration.endpoint = data.get('endpoint', integration.endpoint)
        integration.api_key_name = data.get('api_key_name', integration.api_key_name)
        if data.get('api_secret'):
            integration.api_secret = data.get('api_secret')

        db.session.commit()

        # Log the integration update
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='update_integration',
            status='success',
            details={
                'integration_id': integration.id,
                'integration_name': integration.name,
                'changes': {
                    field: {'old': old_values[field], 'new': getattr(integration, field)}
                    for field in old_values
                    if old_values[field] != getattr(integration, field)
                }
            }
        )

        return jsonify({
            'status': 'success',
            'message': 'Integration updated successfully'
        })

    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='update_integration',
            status='failure',
            details={
                'integration_id': integration_id,
                'error': str(e)
            }
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/integrations/<int:integration_id>', methods=['DELETE'])
@login_required
def delete_integration(integration_id):
    try:
        integration = Integration.query.filter_by(
            id=integration_id,
            user_id=current_user.id
        ).first_or_404()

        integration_info = {
            'id': integration.id,
            'name': integration.name,
            'http_method': integration.http_method,
            'base_url': integration.base_url
        }
        
        db.session.delete(integration)
        db.session.commit()

        # Log the integration deletion
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_integration',
            status='success',
            details=integration_info
        )
        
        return jsonify({'message': 'Integration deleted successfully'})
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_integration',
            status='failure',
            details={
                'integration_id': integration_id,
                'error': str(e)
            }
        )
        return jsonify({
            'error': 'Failed to delete integration',
            'message': str(e)
        }), 500

@bp.route('/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    try:
        users = User.query.all()
        return jsonify({
            'status': 'success',
            'users': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'roles': user.roles,
                'role_names': user.role_names,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            } for user in users]
        })
    except Exception as e:
        print(f"Error fetching users: {str(e)}")  # Debug logging
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/storage-configurations', methods=['POST'])
@login_required
def create_storage_configuration():
    try:
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400

        data = request.get_json()
        print("Creating storage config:", data)

        config = StorageConfig(
            user_id=current_user.id,
            name=data.get('name'),
            storage_type=data.get('storage_type')
        )

        if config.storage_type == 'aws':
            config.credentials = {
                'access_key': data.get('aws_access_key'),
                'secret_key': data.get('aws_secret_key'),
                'region': data.get('aws_region')
            }
            config.bucket_name = data.get('aws_bucket_name')
        else:  # azure
            config.credentials = {
                'connection_string': data.get('azure_connection_string')
            }
            config.container_name = data.get('azure_container_name')

        db.session.add(config)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Storage configuration created successfully'
        })

    except Exception as e:
        db.session.rollback()
        print("Error creating storage config:", str(e))
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/storage-configurations/<int:config_id>', methods=['PUT'])
@login_required
def update_storage_configuration(config_id):
    try:
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400

        data = request.get_json()
        config = StorageConfig.query.filter_by(
            id=config_id,
            user_id=current_user.id
        ).first_or_404()

        # Update fields
        config.name = data.get('name', config.name)
        config.storage_type = data.get('storage_type', config.storage_type)

        if config.storage_type == 'aws':
            config.credentials = {
                'access_key': data.get('aws_access_key'),
                'secret_key': data.get('aws_secret_key'),
                'region': data.get('aws_region')
            }
            config.bucket_name = data.get('aws_bucket_name')
            config.container_name = None
        else:  # azure
            config.credentials = {
                'connection_string': data.get('azure_connection_string')
            }
            config.container_name = data.get('azure_container_name')
            config.bucket_name = None

        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Storage configuration updated successfully',
            'csrf_token': generate_csrf()  # Include new CSRF token in response
        })

    except Exception as e:
        db.session.rollback()
        print("Error updating storage config:", str(e))
        return jsonify({
            'status': 'error',
            'message': str(e),
            'csrf_token': generate_csrf()  # Include new CSRF token in error response
        }), 500

@bp.route('/storage-configurations/<int:config_id>', methods=['GET'])
@login_required
def get_storage_configuration(config_id):
    try:
        config = StorageConfig.query.filter_by(
            id=config_id,
            user_id=current_user.id
        ).first_or_404()
        
        return jsonify({
            'id': config.id,
            'name': config.name,
            'storage_type': config.storage_type,
            'credentials': config.credentials,
            'bucket_name': config.bucket_name,
            'container_name': config.container_name
        })
    except Exception as e:
        print(f"Error fetching storage config: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.route('/storage-configurations/<int:config_id>', methods=['DELETE'])
@login_required
def delete_storage_configuration(config_id):
    try:
        config = StorageConfig.query.filter_by(
            id=config_id,
            user_id=current_user.id
        ).first_or_404()

        config_info = {
            'id': config.id,
            'name': config.name,
            'storage_type': config.storage_type
        }
        
        db.session.delete(config)
        db.session.commit()

        # Log the storage configuration deletion
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_storage_config',
            status='success',
            details=config_info
        )
        
        return jsonify({'status': 'success', 'message': 'Storage configuration deleted successfully'})
    except Exception as e:
        db.session.rollback()
        current_app.audit_logger.log_audit(
            actor=current_user.username,
            action='delete_storage_config',
            status='failure',
            details={
                'config_id': config_id,
                'error': str(e)
            }
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@bp.before_request
def log_api_request():
    # Log API authentication attempts
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        key_prefix = APIKey.get_prefix(api_key)
        
        # Find the API key
        stored_key = APIKey.query.filter_by(key_prefix=key_prefix).first()
        if stored_key:
            if stored_key.check_key(api_key):
                current_app.audit_logger.log_auth(
                    username=f"API Key: {stored_key.key_name}",
                    status='success',
                    details={
                        'key_id': stored_key.id,
                        'user_id': stored_key.user_id,
                        'endpoint': request.endpoint
                    }
                )
            else:
                current_app.audit_logger.log_auth(
                    username=f"API Key: {stored_key.key_name}",
                    status='failure',
                    details={
                        'reason': 'Invalid API key',
                        'endpoint': request.endpoint
                    }
                )
        else:
            current_app.audit_logger.log_auth(
                username="Unknown API Key",
                status='failure',
                details={
                    'reason': 'API key not found',
                    'endpoint': request.endpoint
                }
            ) 