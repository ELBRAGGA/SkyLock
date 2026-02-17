# SkyLock Security Platform

A cloud security platform demonstrating:
- 🔐 JWT Authentication
- 🔑 Role-Based Access Control (RBAC)
- 📝 Audit Logging
- 🔒 Encryption at Rest
- 🚫 Account Lockout

## Features
- Admin/Engineer/Viewer roles
- JWT token authentication
- Encrypted data storage
- Audit logs for all actions
- RESTful API

## Tech Stack
- Python/Flask
- JWT tokens
- SHA-256 hashing
- XOR encryption (KMS simulation)

## Quick Start
```bash
pip3 install flask pyjwt
python3 skylock.py
```

## API Endpoints
- POST /auth/register - Create account
- POST /auth/login - Get JWT token
- POST /secure-data - Store encrypted data
- GET /admin/users - List users (admin only)
- GET /audit-logs - View logs (admin only)

