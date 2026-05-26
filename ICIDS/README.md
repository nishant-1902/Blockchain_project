# ICIDS - Intrusion Detection and Defense System

A comprehensive Flask-based cybersecurity dashboard with real-time threat detection, blockchain-based audit logging, and machine learning-powered intrusion detection. Built with modern frontend technologies (Bootstrap 5, Chart.js, Socket.IO) and production-ready backend infrastructure.

## Table of Contents

- [Features](#features)
- [Project Overview](#project-overview)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [ML Model Training](#ml-model-training)
- [Network Monitoring](#network-monitoring)
- [Real-time Alerts](#real-time-alerts)
- [Report Generation](#report-generation)
- [Authentication](#authentication)
- [Screenshots](#screenshots)
- [Development](#development)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

### 🛡️ Security & Detection
- **Real-time Threat Detection**: ML-powered intrusion detection system analyzing network packets
- **Attack Type Classification**: Automatic identification of DDoS, Port Scans, Brute Force, SQL Injection, and more
- **Blockchain Audit Trail**: Immutable record of all security events using blockchain technology
- **JWT Authentication**: Secure token-based user authentication with role-based access control

### 📊 Monitoring & Analytics
- **Real-time Dashboard**: Live visualization of security events, packet stats, and threat metrics
- **Alert Management**: Centralized alert system with filtering, searching, and status tracking
- **Packet Capture**: Network packet monitoring with detailed protocol analysis
- **Threat Analysis**: Severity classification and threat scoring algorithm

### 📈 Reporting & Export
- **PDF Reports**: Multi-page security reports with executive summaries and threat analysis
- **CSV Export**: Exportable alert data for external analysis and compliance
- **Report History**: Manage and retrieve previously generated reports
- **Statistics Dashboard**: Summary metrics for alerts, threats, and network activity

### 🎨 User Interface
- **Dark-themed Cybersecurity Dashboard**: Professional dark theme with glowing effects
- **Responsive Design**: Mobile-friendly interface with Bootstrap 5
- **Real-time Updates**: Live data synchronization via Socket.IO
- **Interactive Charts**: Attack trends and type distribution visualization with Chart.js

### 🔐 Advanced Features
- **Multi-layer Network Monitoring**: Packet capture using Scapy and Pyshark
- **Geolocation Tracking**: IP geolocation for threat source identification
- **Customizable Alerts**: Alert thresholds and notification preferences
- **User Management**: Registration, login, and role-based permissions

## Project Overview

ICIDS is a full-stack security monitoring platform designed to detect and respond to network-based threats in real-time. It combines traditional network monitoring, machine learning-based anomaly detection, and blockchain technology for comprehensive threat management.

### Key Components:

1. **Frontend Layer**: Bootstrap 5 responsive UI with Socket.IO real-time updates
2. **Backend API**: Flask RESTful API with JWT authentication
3. **Database Layer**: SQLAlchemy ORM with persistent storage
4. **ML Engine**: Machine learning model for threat classification
5. **Blockchain**: Immutable audit trail for security events
6. **Network Monitor**: Packet capture and analysis modules

## Technology Stack

### Backend
- **Flask**: Python web framework
- **SQLAlchemy**: Object-Relational Mapping
- **PyJWT**: JWT authentication
- **FPDF**: PDF report generation
- **Scapy**: Network packet manipulation
- **Pyshark**: Wireshark integration
- **scikit-learn**: Machine learning library
- **pandas**: Data analysis and manipulation

### Frontend
- **Bootstrap 5**: Responsive CSS framework
- **Chart.js**: Data visualization
- **Socket.IO**: Real-time bidirectional communication
- **Jinja2**: Template engine
- **JavaScript ES6**: Client-side logic

### Database & Storage
- **SQLite/PostgreSQL**: Relational database
- **CSV**: Report export format

### Development & Testing
- **Python unittest**: Unit testing framework
- **pytest**: Advanced testing (optional)
- **Flask test client**: API testing

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Virtual environment support
- Network interface access (for packet capture)

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd Blockchain_project/ICIDS
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
Create a `.env` file in the project root:
```env
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
DATABASE_URL=sqlite:///icids.db
DEBUG=True
```

### Step 5: Initialize Database
```bash
python app.py
# Or use Flask CLI:
# flask db init
# flask db migrate
# flask db upgrade
```

### Step 6: Verify Installation
```bash
python -m unittest discover tests/
```

## Quick Start

### Running the Application

```bash
# Activate virtual environment
source venv/bin/activate

# Start Flask development server
python app.py
# Or using Flask CLI:
# flask run

# Server will be available at http://localhost:5000
```

### Accessing the Dashboard
1. Navigate to `http://localhost:5000`
2. Register a new account or login
3. Access the real-time security dashboard
4. Start monitoring network activity

### First Run Checklist
- [ ] Create user account
- [ ] Verify network monitoring is active
- [ ] Check alert feed for recent events
- [ ] Generate sample report
- [ ] Review blockchain audit trail

## Project Structure

```
ICIDS/
├── app.py                           # Main Flask application
├── config.py                        # Configuration settings
├── requirements.txt                 # Python dependencies
│
├── api/
│   └── routes.py                    # RESTful API endpoints
│
├── auth/
│   ├── jwt_auth.py                  # JWT token handling
│   ├── login.py                     # Login functionality
│   ├── register.py                  # User registration
│   └── roles.py                     # Role-based access control
│
├── blockchain/
│   ├── block.py                     # Block definition
│   ├── blockchain.py                # Blockchain logic
│   └── hash_util.py                 # Hashing utilities
│
├── database/
│   └── models.py                    # SQLAlchemy models
│
├── intrusion_detection/
│   ├── detect_attack.py             # Attack detection logic
│   ├── preprocess.py                # Data preprocessing
│   └── train_model.py               # ML model training
│
├── network_monitor/
│   ├── packet_capture.py            # Packet capture base
│   ├── pyshark_monitor.py           # Pyshark integration
│   └── scapy_monitor.py             # Scapy integration
│
├── realtime/
│   ├── alerts.py                    # Alert management
│   └── socket_events.py             # Socket.IO events
│
├── reports/
│   └── report_generator.py          # PDF/CSV report generation
│
├── utils/
│   ├── helpers.py                   # Utility helper functions
│   └── validators.py                # Input validation
│
├── static/
│   ├── css/
│   │   └── style.css                # Dark theme styling
│   └── js/
│       └── app.js                   # Client-side logic
│
├── templates/
│   ├── base.html                    # Base template
│   ├── login.html                   # Login page
│   ├── register.html                # Registration page
│   ├── dashboard.html               # Main dashboard
│   ├── alerts.html                  # Alerts management
│   └── reports.html                 # Report generation
│
├── logs/                            # Application logs
├── tests/
│   └── test_app.py                  # Unit tests
│
└── README.md                        # This file
```

## Configuration

### Environment Variables

```env
# Flask Configuration
FLASK_ENV=development|production
FLASK_APP=app.py
DEBUG=True|False

# Security
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
JWT_EXPIRATION_HOURS=24

# Database
DATABASE_URL=sqlite:///icids.db
# or for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/icids_db

# Network Monitoring
PACKET_CAPTURE_INTERFACE=eth0
PACKET_CAPTURE_TIMEOUT=30

# ML Model
MODEL_PATH=models/threat_detection_model.pkl
THREAT_THRESHOLD=0.7

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/icids.log

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
```

### Database Setup

For SQLite (default):
```bash
python app.py  # Creates icids.db automatically
```

For PostgreSQL:
```bash
# Create database
createdb icids_db

# Update DATABASE_URL in .env
DATABASE_URL=postgresql://user:password@localhost:5432/icids_db

# Run migrations
python app.py
```

## API Documentation

### Authentication Endpoints

#### Register User
```
POST /api/register
Content-Type: application/json

{
  "username": "securityadmin",
  "email": "admin@example.com",
  "password": "SecurePass123!"
}

Response: 201 Created
{
  "message": "User registered successfully",
  "user_id": 1
}
```

#### Login
```
POST /api/login
Content-Type: application/json

{
  "username": "securityadmin",
  "password": "SecurePass123!"
}

Response: 200 OK
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 86400
}
```

### Alert Endpoints

#### Get All Alerts
```
GET /api/alerts
Headers: Authorization: Bearer {token}
Query Parameters:
  - page: Page number (default: 1)
  - per_page: Items per page (default: 20)
  - severity: Filter by severity
  - type: Filter by type
  - status: Filter by status

Response: 200 OK
{
  "alerts": [
    {
      "id": 1,
      "type": "DDoS",
      "severity": "High",
      "description": "DDoS attack detected",
      "source_ip": "192.168.1.100",
      "dest_ip": "10.0.0.1",
      "port": 80,
      "status": "Open",
      "timestamp": "2024-01-15T10:30:00Z",
      "threat_score": 85
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "pages": 8
  }
}
```

#### Create Alert
```
POST /api/alerts
Headers: Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "Port Scan",
  "severity": "Medium",
  "description": "Port scan detected on network",
  "source_ip": "192.168.1.50",
  "dest_ip": "10.0.0.1",
  "port": 22,
  "protocol": "TCP"
}

Response: 201 Created
{
  "id": 1,
  "message": "Alert created successfully"
}
```

#### Get Alert Details
```
GET /api/alerts/{alert_id}
Headers: Authorization: Bearer {token}

Response: 200 OK
{
  "alert": { ...alert details... }
}
```

#### Update Alert
```
PUT /api/alerts/{alert_id}
Headers: Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "Resolved",
  "notes": "Attack source blocked"
}

Response: 200 OK
{
  "message": "Alert updated successfully"
}
```

#### Delete Alert
```
DELETE /api/alerts/{alert_id}
Headers: Authorization: Bearer {token}

Response: 200 OK
{
  "message": "Alert deleted successfully"
}
```

### Report Endpoints

#### Generate Report
```
POST /api/reports/generate
Headers: Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Security Report January 2024",
  "type": "pdf",  # pdf or csv
  "date_range": {
    "start": "2024-01-01",
    "end": "2024-01-31"
  },
  "sections": ["summary", "alerts", "statistics", "recommendations"]
}

Response: 201 Created
{
  "report_id": 1,
  "message": "Report generation started",
  "download_url": "/api/reports/1/download"
}
```

#### Get Reports
```
GET /api/reports
Headers: Authorization: Bearer {token}
Query Parameters:
  - page: Page number
  - per_page: Items per page

Response: 200 OK
{
  "reports": [
    {
      "id": 1,
      "name": "Security Report January 2024",
      "type": "pdf",
      "generated_at": "2024-01-31T23:59:59Z",
      "file_size": 245632,
      "download_url": "/api/reports/1/download"
    }
  ]
}
```

#### Download Report
```
GET /api/reports/{report_id}/download
Headers: Authorization: Bearer {token}

Response: 200 OK
Content-Type: application/pdf (or text/csv)
[Binary file data]
```

### Dashboard Statistics
```
GET /api/dashboard/stats
Headers: Authorization: Bearer {token}

Response: 200 OK
{
  "total_alerts": 1523,
  "active_threats": 12,
  "packets_captured": 1000000,
  "blocked_attacks": 89,
  "critical_alerts": 5,
  "high_alerts": 23,
  "medium_alerts": 156,
  "low_alerts": 1339
}
```

### Network Monitoring
```
GET /api/network/stats
Headers: Authorization: Bearer {token}

Response: 200 OK
{
  "packets_per_second": 1250,
  "bytes_per_second": 2048000,
  "active_connections": 42,
  "top_protocols": [
    {"protocol": "TCP", "count": 5000},
    {"protocol": "UDP", "count": 3000}
  ]
}
```

## ML Model Training

### Data Preparation

The ML model requires network traffic features in the following format:

```python
# Required features for training:
# 1. packet_size - Size of network packet
# 2. packet_rate - Packets per second
# 3. unique_ports - Number of unique ports accessed
# 4. protocol_type - TCP (1), UDP (0)
# 5. payload_entropy - Entropy of packet payload
```

### Training the Model

```bash
# Navigate to intrusion_detection directory
cd intrusion_detection

# Prepare training data
python preprocess.py --input data/network_traffic.csv --output data/processed_data.pkl

# Train model
python train_model.py --data data/processed_data.pkl --model models/threat_model.pkl

# Evaluate model
python train_model.py --evaluate --model models/threat_model.pkl --test-data data/test_data.pkl
```

### Sample Training Data Format (CSV)

```csv
packet_size,packet_rate,unique_ports,protocol_type,payload_entropy,label
256,100,5,1,4.5,0
512,500,20,1,6.2,1
128,50,2,0,3.1,0
1024,2000,100,1,7.8,1
```

### Model Performance Metrics

After training, the model generates:
- Accuracy score
- Precision, Recall, F1-score
- ROC-AUC curve
- Confusion matrix

```bash
# View model statistics
python train_model.py --stats models/threat_model.pkl
```

## Network Monitoring

### Packet Capture Configuration

#### Using Scapy
```bash
# Start packet capture
python network_monitor/scapy_monitor.py --interface eth0 --filter "tcp port 80"
```

#### Using Pyshark
```bash
# Start packet capture with Pyshark
python network_monitor/pyshark_monitor.py --interface eth0 --capture-filter "tcp"
```

### Supported Filters
- `tcp port 80` - HTTP traffic
- `tcp port 443` - HTTPS traffic
- `tcp port 22` - SSH traffic
- `src host 192.168.1.1` - Traffic from specific IP
- `dst port 53` - DNS queries
- `protocol tcp` - All TCP traffic

### Real-time Monitoring
Packet statistics are streamed via Socket.IO to the dashboard in real-time:
- Packets per second
- Bytes per second
- Protocol distribution
- Top source/destination IPs
- Port activity

## Real-time Alerts

### Alert System Architecture

```
Network Monitor -> Packet Analysis -> ML Prediction -> Alert Queue -> Socket.IO -> Dashboard
                                        ↓
                                    Database
                                        ↓
                                    Blockchain
```

### Alert Severity Levels

| Severity | Score Range | Action |
|----------|-------------|--------|
| Critical | 91-100      | Immediate notification & block |
| High     | 71-90       | Alert & investigate |
| Medium   | 51-70       | Log & monitor |
| Low      | 0-50        | Archive & review |

### Alert Statuses
- **Open**: New alert, requires investigation
- **Acknowledged**: Alert reviewed by analyst
- **Resolved**: Threat mitigated or false positive
- **Dismissed**: Alert archived

## Report Generation

### PDF Report Structure
1. **Header** - Report title, date, organization
2. **Executive Summary** - Key findings and statistics
3. **Alert Details** - Comprehensive alert table
4. **Network Statistics** - Traffic and protocol analysis
5. **Threat Analysis** - Attack type breakdown and trends
6. **Recommendations** - Security recommendations
7. **Blockchain Verification** - Audit trail proof
8. **Footer** - Page numbers and timestamps

### CSV Export Fields
- Timestamp
- Alert Type
- Severity
- Description
- Source IP
- Destination IP
- Port
- Status
- Action Taken
- Threat Score

### Report Generation API

```python
from reports.report_generator import ReportGenerator
from database.models import Alert

# Get alerts for report
alerts = Alert.query.filter_by(status='Open').all()

# Initialize generator
generator = ReportGenerator()

# Generate PDF
pdf_path = generator.generate_pdf_report(
    alerts=alerts,
    title="January 2024 Security Report",
    filename="security_report_jan2024.pdf"
)

# Generate CSV
csv_path = generator.generate_csv_report(
    alerts=alerts,
    filename="alerts_jan2024.csv"
)

# Get summary statistics
summary = generator.get_report_summary(alerts)
print(f"Total Alerts: {summary['total_alerts']}")
print(f"Critical: {summary['severity_breakdown']['Critical']}")
```

## Authentication

### JWT Token Structure

```json
{
  "user_id": 1,
  "username": "securityadmin",
  "email": "admin@example.com",
  "roles": ["admin", "analyst"],
  "exp": 1705334400,
  "iat": 1705248000
}
```

### Role-Based Access Control

| Role    | Permissions |
|---------|-------------|
| Admin   | Create users, manage roles, full access |
| Analyst | View alerts, create reports, investigate |
| Monitor | View-only access to dashboard |

### Token Management

Tokens are stored in browser localStorage and automatically:
- Attached to API requests in Authorization header
- Refreshed on expiration
- Cleared on logout
- Validated server-side on each request

## Screenshots

### Dashboard
- Real-time threat statistics and charts
- Active alerts feed
- Network monitoring metrics
- System status indicators

### Alerts Management
- Searchable alert table
- Filtering by severity, type, status
- Detail modal with full alert information
- Bulk actions support

### Reports
- Report generation form
- Report history table
- PDF/CSV download options
- Report metadata display

### Authentication
- Secure login page
- User registration with validation
- Password strength meter
- Session management

*Screenshots directory can be populated with actual application screenshots*

## Development

### Development Environment Setup

```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Install pre-commit hooks
pre-commit install

# Run development server with auto-reload
FLASK_ENV=development FLASK_DEBUG=True python app.py
```

### Code Style

```bash
# Format code with Black
black .

# Lint with Flake8
flake8 . --max-line-length=100

# Type checking with mypy (optional)
mypy . --ignore-missing-imports
```

### Database Migrations

```bash
# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Rollback migration
flask db downgrade
```

## Testing

### Running Tests

```bash
# Run all tests
python -m unittest discover tests/

# Run specific test class
python -m unittest tests.test_app.UserRegistrationTestCase

# Run specific test
python -m unittest tests.test_app.UserRegistrationTestCase.test_register_with_valid_data

# Run with pytest
pytest tests/ -v
```

### Test Coverage

```bash
# Generate coverage report
coverage run -m unittest discover
coverage report
coverage html  # Generate HTML report in htmlcov/
```

### Test Categories

1. **Unit Tests** - Individual function testing
2. **Integration Tests** - Database and API interaction
3. **Authentication Tests** - JWT and role-based access
4. **ML Tests** - Model prediction accuracy
5. **Performance Tests** - Response time and load testing

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find and kill process using port 5000
lsof -i :5000
kill -9 <PID>

# Or use different port
FLASK_PORT=5001 python app.py
```

#### Database Connection Error
```bash
# Verify database URL in .env
# For SQLite, ensure directory exists:
mkdir -p data
# Reinitialize database:
python app.py
```

#### Packet Capture Permission Denied
```bash
# Grant packet capture privileges (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3

# Or run with sudo
sudo python app.py
```

#### ML Model Not Found
```bash
# Train model first
cd intrusion_detection
python train_model.py --data training_data.csv

# Verify model exists
ls -la models/threat_model.pkl
```

#### Socket.IO Connection Issues
```bash
# Check WebSocket support in browser console
# Verify server is running on correct host/port
# Check firewall rules for port 5000
# Try different Socket.IO transport:
# In app.js, set: socket = io({transport: ['websocket']})
```

### Debug Mode

Enable detailed logging:
```python
# In config.py
DEBUG = True
LOG_LEVEL = 'DEBUG'

# In terminal
export FLASK_ENV=development
export FLASK_DEBUG=True
python app.py
```

### Performance Optimization

```bash
# Profile application
python -m cProfile -s cumtime app.py

# Monitor memory usage
python -m memory_profiler app.py

# Load testing
ab -n 1000 -c 10 http://localhost:5000/api/alerts
```

## Contributing

### Contribution Guidelines

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Follow code style guidelines (Black, Flake8)
4. Add tests for new features
5. Ensure all tests pass
6. Commit with clear messages
7. Push to branch and create Pull Request

### Reporting Issues

When reporting issues, include:
- Python version and OS
- Error messages and stack traces
- Steps to reproduce
- Expected vs actual behavior
- Relevant code snippets

## License

This project is licensed under the MIT License - see LICENSE file for details.

---

**ICIDS Version**: 1.0.0  
**Last Updated**: January 2024  
**Maintainer**: Security Development Team

For support and questions, please contact: support@icids-project.com

### Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Socket.IO Documentation](https://socket.io/)
- [Bootstrap 5 Documentation](https://getbootstrap.com/docs/5.0/)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
