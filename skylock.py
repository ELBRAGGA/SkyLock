# skylock.py
import json
import hashlib
import hmac
import os
import datetime
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# ========== DATA LAYER (simulates AWS DynamoDB) ==========
class Database:
    def __init__(self):
        self.users = {}
        self.audit_logs = []
        self.files = {}
    
    def save_user(self, username, user_data):
        self.users[username] = user_data
    
    def get_user(self, username):
        return self.users.get(username)
    
    def log_event(self, event_type, user, details):
        log_entry = {
            'timestamp': str(datetime.datetime.now()),
            'event_type': event_type,
            'user': user,
            'details': details
        }
        self.audit_logs.append(log_entry)
        print(f"[AUDIT] {log_entry}")

db = Database()

# ========== IAM LAYER (simulates AWS IAM) ==========
class IAM:
    ROLES = {
        'admin': {'max_storage': 1000000, 'can_delete': True, 'can_invite': True},
        'engineer': {'max_storage': 100000, 'can_delete': False, 'can_invite': False},
        'viewer': {'max_storage': 10000, 'can_delete': False, 'can_invite': False}
    }
    
    @staticmethod
    def hash_password(password, salt=None):
        if not salt:
            salt = os.urandom(16).hex()
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return f"{salt}${hashed}"
    
    @staticmethod
    def verify_password(stored, provided):
        salt, hash_val = stored.split('$')
        return IAM.hash_password(provided, salt) == stored
    
    @staticmethod
    def create_token(username, role):
        payload = {
            'username': username,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# ========== ENCRYPTION LAYER (simulates AWS KMS) ==========
class KMS:
    def __init__(self):
        self.keys = {}
    
    def create_key(self, key_id):
        self.keys[key_id] = os.urandom(32)
        return key_id
    
    def encrypt(self, key_id, data):
        if key_id not in self.keys:
            return None
        # Simple XOR "encryption" for demo
        key = self.keys[key_id]
        encrypted = bytearray()
        for i, byte in enumerate(data.encode()):
            encrypted.append(byte ^ key[i % len(key)])
        return encrypted.hex()
    
    def decrypt(self, key_id, encrypted_hex):
        if key_id not in self.keys:
            return None
        key = self.keys[key_id]
        encrypted = bytes.fromhex(encrypted_hex)
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ key[i % len(key)])
        return decrypted.decode()

kms = KMS()
kms.create_key("master-key")

# ========== API ENDPOINTS ==========
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': str(datetime.datetime.now())})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'viewer')
    
    if db.get_user(username):
        return jsonify({'error': 'User exists'}), 400
    
    if role not in IAM.ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    
    user = {
        'username': username,
        'password_hash': IAM.hash_password(password),
        'role': role,
        'created_at': str(datetime.datetime.now()),
        'mfa_enabled': False,
        'failed_logins': 0,
        'locked': False
    }
    
    db.save_user(username, user)
    db.log_event('USER_REGISTERED', username, {'role': role})
    
    return jsonify({'message': 'User created', 'username': username})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = db.get_user(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user.get('locked', False):
        return jsonify({'error': 'Account locked'}), 403
    
    if not IAM.verify_password(user['password_hash'], password):
        user['failed_logins'] = user.get('failed_logins', 0) + 1
        if user['failed_logins'] >= 5:
            user['locked'] = True
            db.log_event('ACCOUNT_LOCKED', username, {'reason': 'Failed logins'})
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Reset failed logins on success
    user['failed_logins'] = 0
    token = IAM.create_token(username, user['role'])
    
    db.log_event('LOGIN_SUCCESS', username, {})
    
    return jsonify({
        'token': token,
        'role': user['role'],
        'message': 'Login successful'
    })

@app.route('/secure-data', methods=['POST'])
def store_secure_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['username']
        user = db.get_user(username)
        
        data = request.json.get('data')
        encrypted = kms.encrypt('master-key', data)
        
        if username not in db.files:
            db.files[username] = []
        
        file_record = {
            'id': len(db.files[username]) + 1,
            'encrypted_data': encrypted,
            'created_at': str(datetime.datetime.now())
        }
        db.files[username].append(file_record)
        
        db.log_event('DATA_STORED', username, {'file_id': file_record['id']})
        
        return jsonify({'message': 'Data stored', 'file_id': file_record['id']})
    
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/audit-logs', methods=['GET'])
def get_audit_logs():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['role'] != 'admin':
            return jsonify({'error': 'Admin only'}), 403
        
        return jsonify({'logs': db.audit_logs})
    
    except:
        return jsonify({'error': 'Unauthorized'}), 401
@app.route('/admin/users', methods=['GET'])
def list_users():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['role'] != 'admin':
            return jsonify({'error': 'Admin only'}), 403
        
        users_list = []
        for username, user_data in db.users.items():
            users_list.append({
                'username': username,
                'role': user_data['role'],
                'created_at': user_data['created_at'],
                'locked': user_data.get('locked', False)
            })
        
        return jsonify({'users': users_list})
    
    except:
        return jsonify({'error': 'Unauthorized'}), 401
if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════╗
    ║         SkyLock Security Platform     ║
    ║     Zero Trust Architecture Demo      ║
    ╚═══════════════════════════════════════╝
    """)
    print("🚀 Starting SkyLock API server...")
    print("📡 Endpoints:")
    print("   POST /auth/register - Create account")
    print("   POST /auth/login - Get JWT token")
    print("   POST /secure-data - Store encrypted data")
    print("   GET  /audit-logs - View logs (admin only)")
    print("   GET  /health - Health check")
    print("\n💡 Run with: python skylock.py")
    print("🔑 Test with: curl commands or Postman\n")
    
    app.run(debug=True, port=5000)