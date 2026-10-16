CYBERSECURITY INCIDENT & THREAT MANAGEMENT SYSTEM

Project Overview

The Cybersecurity Incident & Threat Management System is a backend application developed using FastAPI and Python. It helps manage cybersecurity incidents, security alerts, vulnerabilities, risk assessments, remediation activities, and security operations through REST APIs.

The application includes authentication, authorization, organization and asset management, incident tracking, audit logging, and dashboard functionality.

Technologies Used

- Python
- FastAPI
- SQLAlchemy
- SQLite
- JWT Authentication
- Password Hashing
- Pydantic
- Pytest
- Uvicorn
- Alembic for database migrations, if configured

Key Features

1. Authentication and Authorization
   - User registration and login
   - JWT access and refresh tokens
   - Password hashing
   - Password reset
   - User activation and deactivation
   - Current user information
   - Logout and token invalidation
   - Role-based access control

2. Organization and Asset Management
   - Organization management
   - Security team management
   - Asset inventory management

3. Security Incident Management
   - Security alert management
   - Incident tracking and management
   - Alert and incident correlation
   - Investigation management
   - Security playbook management

4. Vulnerability and Risk Management
   - Vulnerability tracking
   - Risk assessment
   - Remediation task management
   - Service-level agreement tracking

5. Monitoring and Reporting
   - Audit logs
   - Notifications
   - Security dashboard
   - Search and reporting functionality

Project Structure

The project is organized into modules to separate API endpoints, database operations, business logic, validation, and testing.

app/
    api/
    core/
    db/
    models/
    schemas/
    services/
    repositories/
    utils/
    main.py

tests/

.env
requirements.txt
README.md

Note: The structure above is a simplified overview. The actual files and subdirectories depend on the final project implementation.

Installation and Setup

1. Clone or download the project.

2. Open the project directory in your terminal.

3. Create a virtual environment.

python -m venv venv

4. Activate the virtual environment in Windows PowerShell.

.\venv\Scripts\Activate.ps1

5. Install the dependencies.

pip install -r requirements.txt

6. Configure the environment variables in the .env file according to the application's settings.

7. Start the development server.

uvicorn app.main:app --reload

Running the Application

After starting the server, open the following URLs in your browser.

Application:
http://127.0.0.1:8000

Interactive API documentation:
http://127.0.0.1:8000/docs

Alternative API documentation:
http://127.0.0.1:8000/redoc

Database

The project uses SQLAlchemy for database operations and SQLite as the database.

Database configuration and connection settings are managed by the application's database module and environment configuration.

If Alembic is configured, it can be used to manage database schema migrations.

Running Tests

Run the complete test suite using:

pytest

To display detailed test results:

pytest -v

To generate a test coverage report:

pytest --cov=app --cov-report=term-missing --cov-report=html

After generating the HTML coverage report, open:

htmlcov/index.html

Security Considerations

- Passwords are stored using password hashing rather than plain text.
- JWT tokens are used for authentication.
- Access to protected endpoints is controlled through authentication and authorization.
- Environment variables are used for application configuration.
- Input validation is handled through FastAPI and Pydantic schemas.

Expected Use Cases

- Register and authenticate users.
- Manage organizations, security teams, and assets.
- Record and investigate security incidents.
- Track alerts and vulnerabilities.
- Assess security risks.
- Manage remediation tasks and incident SLAs.
- Review audit records, notifications, and dashboard information.

Conclusion

The Cybersecurity Incident & Threat Management System provides a modular REST API backend for managing cybersecurity incidents and security operations. It combines authentication, incident response, vulnerability management, risk assessment, and testing into a single application.

The project is designed to support maintainable code, API-based integration, and automated testing.
