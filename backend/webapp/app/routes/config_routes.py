from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..models import StorageConfig, LoggingConfig, db, APIKey, ScannerConfig, Submission, Integration
from ..forms import StorageConfigForm, LoggingConfigForm, APIKeyForm, ScannerConfigForm, IntegrationForm
import boto3
from azure.storage.blob import BlobServiceClient
import os
import time
import requests
import json
from datetime import datetime, timedelta

bp = Blueprint('config_routes', __name__)

@bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    # Fake data for demonstration
    fake_cases = [
        {
            'submission_date': datetime.now() - timedelta(days=i),
            'case_number': f'CASE-{2024000 + i}',
            'case_url': f'https://support-portal.example.com/cases/CASE-{2024000 + i}',
            'incident_number': f'INC-{1024000 + i}',
            'incident_url': f'https://incident-portal.example.com/incidents/INC-{1024000 + i}',
            'is_malicious': True
        }
        for i in range(5)  # Generate 5 fake cases
    ]
    
    return render_template('dashboard.html',
                         recent_cases=fake_cases)

@bp.route('/api/validate-storage', methods=['POST'])
@login_required
def validate_storage():
    storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
    
    if not storage_config:
        return jsonify({'status': 'error', 'message': 'No storage configuration found'})
    
    try:
        if storage_config.storage_type == 'aws':
            session = boto3.Session(
                aws_access_key_id=storage_config.credentials['access_key'],
                aws_secret_access_key=storage_config.credentials['secret_key'],
                region_name=storage_config.credentials['region']
            )
            s3 = session.client('s3')
            s3.head_bucket(Bucket=storage_config.bucket_name)
        else:
            blob_service_client = BlobServiceClient.from_connection_string(
                storage_config.credentials['connection_string']
            )
            container_client = blob_service_client.get_container_client(storage_config.container_name)
            container_client.get_container_properties()
        
        return jsonify({'status': 'success', 'message': 'Connection successful'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api/test-logging', methods=['POST'])
@login_required
def test_logging():
    logging_config = LoggingConfig.query.filter_by(user_id=current_user.id).first()
    
    if not logging_config:
        return jsonify({'status': 'error', 'message': 'No logging configuration found'})
    
    try:
        # Test logging based on destination
        if logging_config.log_destination == 'file':
            # Test file writing permissions
            test_path = os.path.dirname(logging_config.file_path)
            if not os.path.exists(test_path):
                os.makedirs(test_path)
            with open(logging_config.file_path, 'a') as f:
                f.write('Test log entry\n')
                
        elif logging_config.log_destination == 'cloudwatch':
            # Test CloudWatch connection
            cloudwatch = boto3.client('logs')
            cloudwatch.put_log_events(
                logGroupName=logging_config.cloudwatch_group,
                logStreamName=logging_config.cloudwatch_stream,
                logEvents=[{
                    'timestamp': int(time.time() * 1000),
                    'message': 'Test log entry'
                }]
            )
            
        elif logging_config.log_destination == 'azure_monitor':
            # Test Azure Monitor connection
            # Implementation depends on Azure SDK
            pass
        
        return jsonify({'status': 'success', 'message': 'Logging test successful'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp.route('/api-keys', methods=['GET', 'POST'])
@login_required
def api_keys():
    form = APIKeyForm()
    new_key = None
    
    if form.validate_on_submit():
        api_key = APIKey.generate_key()
        key = APIKey(
            user_id=current_user.id,
            key_name=form.key_name.data
        )
        key.set_key(api_key)
        db.session.add(key)
        db.session.commit()
        new_key = api_key
        
    api_keys = APIKey.query.filter_by(user_id=current_user.id).order_by(APIKey.created_at.desc()).all()
    return render_template('api_keys.html', form=form, api_keys=api_keys, new_key=new_key)

@bp.route('/api-keys/<int:key_id>/toggle', methods=['POST'])
@login_required
def toggle_api_key(key_id):
    key = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    key.enabled = not key.enabled
    db.session.commit()
    flash(f'API key {"enabled" if key.enabled else "disabled"} successfully', 'success')
    return redirect(url_for('config_routes.api_keys'))

@bp.route('/api-keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_api_key(key_id):
    key = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    db.session.delete(key)
    db.session.commit()
    flash('API key deleted successfully', 'success')
    return redirect(url_for('config_routes.api_keys'))

@bp.route('/scanners', methods=['GET', 'POST'])
@login_required
def scanners():
    form = ScannerConfigForm()
    if form.validate_on_submit():
        try:
            scanner = ScannerConfig(
                user_id=current_user.id,
                name=form.name.data,
                scanner_type=form.scanner_type.data,
                base_url=form.base_url.data.rstrip('/'),
                endpoint=form.endpoint.data.lstrip('/'),
                http_method=form.http_method.data,
                headers=json.loads(form.headers.data or '{}'),
                query_params=json.loads(form.query_params.data or '{}'),
                body_template=json.loads(form.body_template.data or '{}'),
                response_mapping=json.loads(form.response_mapping.data or '{}'),
                enabled=form.enabled.data
            )
            db.session.add(scanner)
            db.session.commit()
            flash('Scanner configuration added successfully', 'success')
            return redirect(url_for('config_routes.scanners'))
        except json.JSONDecodeError:
            flash('Invalid JSON format in one of the fields', 'danger')
        except Exception as e:
            flash(f'Error adding scanner: {str(e)}', 'danger')
    
    scanners = ScannerConfig.query.filter_by(user_id=current_user.id).all()
    return render_template('scanners.html', form=form, scanners=scanners)

@bp.route('/scanners/<int:scanner_id>/test', methods=['POST'])
@login_required
def test_scanner(scanner_id):
    scanner = ScannerConfig.query.filter_by(
        id=scanner_id,
        user_id=current_user.id
    ).first_or_404()
    
    try:
        # Prepare test data based on scanner type
        if scanner.scanner_type == 'url':
            test_data = 'https://example.com'
        else:  # IP scanner
            test_data = '8.8.8.8'
        
        # Prepare request
        url = f"{scanner.base_url.rstrip('/')}/{scanner.endpoint.lstrip('/')}"
        headers = scanner.headers or {}
        params = scanner.query_params or {}
        body = scanner.body_template or {}
        
        # Replace placeholders in body template
        if isinstance(body, dict):
            body = {k: v.replace('{{input}}', test_data) if isinstance(v, str) else v 
                   for k, v in body.items()}
        
        # Make request
        response = requests.request(
            method=scanner.http_method,
            url=url,
            headers=headers,
            params=params,
            json=body if scanner.http_method in ['POST', 'PUT'] else None,
            timeout=10
        )
        
        response.raise_for_status()
        
        # Update scanner status
        scanner.last_test = datetime.utcnow()
        scanner.test_status = True
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Scanner test successful',
            'response': response.json()
        })
        
    except Exception as e:
        scanner.last_test = datetime.utcnow()
        scanner.test_status = False
        db.session.commit()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400 

@bp.route('/configuration', methods=['GET'])
@login_required
def configuration():
    storage_form = StorageConfigForm()
    logging_form = LoggingConfigForm()
    integration_form = IntegrationForm()
    
    # Get existing configurations
    storage_config = StorageConfig.query.filter_by(user_id=current_user.id).first()
    logging_config = LoggingConfig.query.filter_by(user_id=current_user.id).first()
    integrations = Integration.query.filter_by(user_id=current_user.id).all()

    return render_template('configuration.html',
                         storage_form=storage_form,
                         logging_form=logging_form,
                         integration_form=integration_form,
                         storage_config=storage_config,
                         logging_config=logging_config,
                         integrations=integrations)

@bp.route('/storage', methods=['GET'])
@login_required
def storage():
    form = StorageConfigForm()
    return render_template('configuration/storage.html', form=form)

@bp.route('/configuration/logging', methods=['POST'])
@login_required
def save_logging():
    # Handle logging configuration save
    logging_type = request.form.get('logging_type')
    
    if logging_type == 'aws':
        # Save AWS configuration
        pass
    elif logging_type == 'azure':
        # Save Azure configuration
        pass
        
    flash('Logging configuration saved successfully', 'success')
    return redirect(url_for('config_routes.configuration'))

@bp.route('/configuration/integration', methods=['POST'])
@login_required
def save_integration():
    try:
        print("Received form data:", request.form)  # Debug print
        form = IntegrationForm()
        
        if form.validate_on_submit():
            try:
                integration = Integration(
                    user_id=current_user.id,
                    name=form.name.data,
                    http_method=form.http_method.data,
                    base_url=form.base_url.data,
                    endpoint=form.endpoint.data,
                    api_key_name=form.api_key_name.data,
                    api_secret=form.api_secret.data
                )
                db.session.add(integration)
                db.session.commit()
                
                return jsonify({
                    'status': 'success',
                    'message': 'Integration saved successfully'
                })
            except Exception as e:
                db.session.rollback()
                print(f"Error saving integration: {str(e)}")  # Debug print
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500
        else:
            print("Form validation errors:", form.errors)  # Debug print
            return jsonify({
                'status': 'error',
                'message': 'Validation failed',
                'errors': {field: errors[0] for field, errors in form.errors.items()}
            }), 400
    except Exception as e:
        print(f"Unexpected error: {str(e)}")  # Debug print
        return jsonify({
            'status': 'error',
            'message': f'Unexpected error: {str(e)}'
        }), 500

@bp.route('/configuration/integration/<int:integration_id>/delete', methods=['POST'])
@login_required
def delete_integration(integration_id):
    integration = Integration.query.filter_by(
        id=integration_id, 
        user_id=current_user.id
    ).first_or_404()
    
    db.session.delete(integration)
    db.session.commit()
    flash('Integration deleted successfully', 'success')
    return redirect(url_for('config_routes.configuration')) 