# Email Reporter Tool

A security tool for analyzing suspicious emails and managing analysis results. The system consists of two main components: a web application for user interaction and an email analyzer service for processing emails.

## Project Structure 

reporter-tool/
├── webapp/ # Web application
│ ├── app/ # Flask application
│ │ ├── logs/ # Application logs
│ │ ├── models/ # Database models
│ │ ├── routes/ # API and web routes
│ │ └── templates/ # HTML templates
│ ├── scripts/ # Utility scripts
│ ├── requirements.txt # Python dependencies
│ ├── setup_app.sh # Web app setup script
│ └── run.py # Application entry point
├── email-analyzer/ # Email analysis service
│ ├── requirements.txt # Service dependencies
│ └── analyzer.py # Analysis service entry point
├── run.sh # Main run script
└── setup.py # Project setup script


## Installation

1. Clone the repository and set up the environment:

```
bash
git clone <repository-url>
cd reporter-tool
./setup.py
```

2. Set up the web application:

```
bash
cd webapp
./setup_app.sh
```

This will create:

### Users (all with password: password123)
- 3 basic users (user1, user2, user3)
- 3 analysts (analyst1, analyst2, analyst3)
- 3 engineers (engineer1, engineer2, engineer3)
- 3 admins (admin1, admin2, admin3)
- 3 multi-role users (multi1, multi2, multi3)

### Sample Configurations
- AWS Production storage
- Azure Development storage
- VirusTotal integration
- AlienVault OTX integration

### System API Keys
- Email Analysis Service
- Threat Intelligence Service
- Incident Management Service
- Automation Service

### Sample Data
- 6 months of submission history
- 30 days of logs (audit, authentication, usage)

## Running the Application

Start the entire application:

```
bash
./run.sh
```

Or start components individually:

1. Web Application:

```
bash
cd webapp
python run.py
```

2. Email Analyzer:

```
bash
cd email-analyzer
python analyzer.py
```

## Roles and Permissions

- **User**: Basic email submission and viewing
- **Analyst**: Analysis and reporting capabilities
- **Engineer**: Configuration and integration management
- **Admin**: Full system access and user management

## Logging

Logs are stored in `webapp/app/logs/`:
- `audit.log`: System changes and user actions
- `authentication.log`: Login attempts and API usage
- `usage.log`: Feature usage and statistics

Logs can be viewed and managed in the Admin Dashboard.