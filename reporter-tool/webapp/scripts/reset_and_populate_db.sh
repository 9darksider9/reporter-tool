#!/bin/bash

# Create the directory if it doesn't exist
mkdir -p scripts

# Create Python script for database operations
cat > scripts/populate_db.py << 'EOF'
from app import create_app, db
from app.models import User, StorageConfig, Integration, APIKey, Submission, Role
from datetime import datetime, timedelta
import random
import json
import os

def reset_database():
    app = create_app()
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        
        # Create roles
        roles = {
            'user': Role(name='user', description='Basic user role'),
            'analyst': Role(name='analyst', description='Security analyst role'),
            'engineer': Role(name='engineer', description='Security engineer role'),
            'admin': Role(name='admin', description='Administrator role')
        }
        for role in roles.values():
            db.session.add(role)
        db.session.commit()

        # Create users with different role combinations
        users = []
        
        # Single role users
        for i in range(3):
            users.extend([
                User(username=f'user{i+1}', email=f'user{i+1}@example.com', roles=['user']),
                User(username=f'analyst{i+1}', email=f'analyst{i+1}@example.com', roles=['analyst']),
                User(username=f'engineer{i+1}', email=f'engineer{i+1}@example.com', roles=['engineer']),
                User(username=f'admin{i+1}', email=f'admin{i+1}@example.com', roles=['admin'])
            ])

        # Multi-role users
        role_combinations = [
            ['analyst', 'engineer'],
            ['analyst', 'admin'],
            ['engineer', 'admin']
        ]
        for i, roles in enumerate(role_combinations):
            users.append(User(
                username=f'multi{i+1}',
                email=f'multi{i+1}@example.com',
                roles=roles
            ))

        # Set password and add users
        for user in users:
            user.set_password('password123')
            db.session.add(user)
        db.session.commit()

        # Create storage configurations
        storage_configs = [
            StorageConfig(
                user_id=1,
                name='AWS Production',
                storage_type='aws',
                credentials={
                    'access_key': 'fake_access_key_1',
                    'secret_key': 'fake_secret_key_1',
                    'region': 'us-east-1'
                },
                bucket_name='prod-artifacts'
            ),
            StorageConfig(
                user_id=1,
                name='Azure Development',
                storage_type='azure',
                credentials={
                    'connection_string': 'fake_connection_string'
                },
                container_name='dev-artifacts'
            )
        ]
        for config in storage_configs:
            db.session.add(config)

        # Create integrations
        integrations = [
            Integration(
                user_id=1,
                name='VirusTotal',
                http_method='GET',
                base_url='https://www.virustotal.com/vtapi/v2',
                endpoint='/file/report',
                api_key_name='apikey'
            ),
            Integration(
                user_id=1,
                name='AlienVault OTX',
                http_method='GET',
                base_url='https://otx.alienvault.com/api/v1',
                endpoint='/indicators/submit',
                api_key_name='X-OTX-API-KEY'
            )
        ]
        for integration in integrations:
            db.session.add(integration)

        # Create system API keys
        system_apis = [
            ('email_analyzer', 'Email Analysis Service'),
            ('threat_intel', 'Threat Intelligence Service'),
            ('incident_manager', 'Incident Management Service'),
            ('automation', 'Automation Service')
        ]
        for name, description in system_apis:
            key = APIKey(
                user_id=1,
                key_name=name,
                description=description,
                is_system_key=True
            )
            key.set_key(APIKey.generate_key())
            db.session.add(key)

        # Generate submissions for dashboard data
        start_date = datetime.now() - timedelta(days=180)
        for i in range(1000):
            submission_date = start_date + timedelta(
                days=random.randint(0, 180),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            is_malicious = random.random() < 0.3  # 30% chance of being malicious
            
            submission = Submission(
                user_id=random.randint(1, len(users)),
                email_id=f'email_{i}',
                submission_date=submission_date,
                status='completed',
                is_malicious=is_malicious,
                score=random.randint(0, 100),
                analysis_result={
                    'urls': random.randint(0, 5),
                    'attachments': random.randint(0, 3),
                    'indicators': random.randint(0, 10)
                }
            )
            db.session.add(submission)

        db.session.commit()

        # Generate fake logs
        log_types = ['audit', 'authentication', 'usage']
        actions = {
            'audit': ['create_user', 'delete_user', 'update_config', 'create_api_key'],
            'authentication': ['login_success', 'login_failure', 'logout', 'api_auth'],
            'usage': ['submit_email', 'view_report', 'download_artifact']
        }
        
        log_dir = os.path.join(app.root_path, 'logs')
        os.makedirs(log_dir, exist_ok=True)

        for log_type in log_types:
            with open(os.path.join(log_dir, f'{log_type}.log'), 'w') as f:
                start_date = datetime.now() - timedelta(days=30)
                for i in range(100):
                    timestamp = start_date + timedelta(
                        days=random.randint(0, 30),
                        hours=random.randint(0, 23),
                        minutes=random.randint(0, 59)
                    )
                    user = random.choice(users)
                    action = random.choice(actions[log_type])
                    status = 'success' if random.random() < 0.9 else 'failure'
                    
                    log_entry = {
                        'timestamp': timestamp.isoformat(),
                        'actor': user.username,
                        'action': action,
                        'status': status,
                        'details': {
                            'ip_address': f'192.168.1.{random.randint(1, 255)}',
                            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                        }
                    }
                    
                    f.write(f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} {json.dumps(log_entry)}\n')

if __name__ == '__main__':
    reset_database()
    print("Database reset and populated with fake data successfully!")
EOF

# Make the script executable
chmod +x scripts/populate_db.py

# Create a Python virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment and run the population script
source venv/bin/activate
pip install -r requirements.txt
python scripts/populate_db.py

echo "Database has been reset and populated with fake data!" 