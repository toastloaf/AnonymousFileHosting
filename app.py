"""
Secure Anonymous File Hosting Service
A Flask-based file hosting service with encryption and anonymous account system.
"""

import os
import secrets
import hashlib
import logging
from pathlib import Path
from datetime import timedelta, datetime
from functools import wraps

from flask import Flask, jsonify, render_template, request, make_response, send_file, session, redirect
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from cryptography.fernet import Fernet
import pymongo
from pymongo.errors import ConnectionFailure, DuplicateKeyError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 5  # 5GB max file size
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# MongoDB configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'filehosting')
MONGO_COLLECTION_NAME = os.environ.get('MONGO_COLLECTION_NAME', 'accounts')

# Data directory
DATA_DIR = Path(os.environ.get('DATA_DIR', './data'))
DATA_DIR.mkdir(exist_ok=True)

# Initialize MongoDB connection pool
try:
    mongo_client = pymongo.MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000,
        maxPoolSize=50
    )
    # Test connection
    mongo_client.admin.command('ping')
    db = mongo_client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    # Create index on account number for faster lookups
    collection.create_index("account_number", unique=True)
    logger.info("Connected to MongoDB successfully")
except ConnectionFailure as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise


def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        account_number = session.get('account_number')
        if not account_number:
            return jsonify({"error": "Authentication required"}), 401
        
        # Verify account exists
        try:
            account = collection.find_one({"account_number": account_number})
            if not account:
                session.clear()
                return jsonify({"error": "Account not found"}), 401
        except Exception as e:
            logger.error(f"Error verifying account: {e}")
            return jsonify({"error": "Authentication failed"}), 500
        
        return f(account_number, *args, **kwargs)
    return decorated_function


def get_user_data_dir(account_number):
    """Get the data directory for a user account."""
    user_dir = DATA_DIR / str(account_number)
    user_dir.mkdir(exist_ok=True)
    return user_dir


def get_user_key_path(account_number):
    """Get the path to the user's encryption key file."""
    return get_user_data_dir(account_number) / 'encryption.key'


def generate_encryption_key(account_number):
    """Generate and save an encryption key for a user."""
    key = Fernet.generate_key()
    key_path = get_user_key_path(account_number)
    
    with open(key_path, 'wb') as f:
        f.write(key)
    
    return key


def get_encryption_key(account_number):
    """Load the encryption key for a user."""
    key_path = get_user_key_path(account_number)
    
    if not key_path.exists():
        raise FileNotFoundError("Encryption key not found")
    
    with open(key_path, 'rb') as f:
        return f.read()


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file size limit exceeded."""
    return jsonify({"error": "File size exceeds maximum limit (5GB)"}), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "An internal error occurred"}), 500


@app.route('/')
def index():
    """Render the login page."""
    return render_template('index.html')


@app.route('/api/create-account', methods=['POST'])
def create_account():
    """Create a new anonymous account."""
    try:
        # Generate unique account number
        max_attempts = 10
        for _ in range(max_attempts):
            account_number = secrets.randbelow(9999999999) + 1
            
            try:
                # Insert account into database
                doc = {"account_number": account_number, "created_at": datetime.utcnow()}
                collection.insert_one(doc)
                
                # Generate encryption key
                generate_encryption_key(account_number)
                
                logger.info(f"Created account: {account_number}")
                
                # Set session
                session.permanent = True
                session['account_number'] = account_number
                
                return jsonify({
                    "success": True,
                    "account_number": account_number,
                    "message": "Account created successfully"
                }), 201
                
            except DuplicateKeyError:
                # Account number collision, try again
                continue
        
        return jsonify({"error": "Failed to create account. Please try again."}), 500
        
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        return jsonify({"error": "Failed to create account"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """Login with an existing account number."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        
        account_number = data.get('account_number')
        if not account_number:
            return jsonify({"error": "Account number is required"}), 400
        
        try:
            account_number = int(account_number)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid account number format"}), 400
        
        # Verify account exists
        account = collection.find_one({"account_number": account_number})
        if not account:
            return jsonify({"error": "Account not found"}), 404
        
        # Set session
        session.permanent = True
        session['account_number'] = account_number
        
        logger.info(f"User logged in: {account_number}")
        
        return jsonify({
            "success": True,
            "message": "Login successful"
        }), 200
        
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "Login failed"}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout the current user."""
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"}), 200


@app.route('/dashboard')
def dashboard():
    """Render the dashboard page."""
    account_number = session.get('account_number')
    if not account_number:
        return redirect('/')
    
    # Verify account exists
    account = collection.find_one({"account_number": account_number})
    if not account:
        session.clear()
        return redirect('/')
    
    return render_template('dashboard.html', account_number=account_number)


@app.route('/api/files', methods=['GET'])
@require_auth
def get_files(account_number):
    """Get list of files for the authenticated user."""
    try:
        user_dir = get_user_data_dir(account_number)
        files = []
        
        for file_path in user_dir.iterdir():
            if file_path.is_file() and file_path.name != 'encryption.key':
                size_bytes = file_path.stat().st_size
                size_mb = round(size_bytes / (1024 * 1024), 2)
                
                files.append({
                    'name': file_path.name,
                    'size_mb': size_mb,
                    'size_bytes': size_bytes
                })
        
        return jsonify({"success": True, "files": files}), 200
        
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({"error": "Failed to retrieve files"}), 500


@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file(account_number):
    """Upload a file for the authenticated user."""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Get client-side hash
        client_hash = request.form.get('file_hash')
        if not client_hash:
            return jsonify({"error": "File hash is required"}), 400
        
        # Read file content
        file_content = file.read()
        
        # Verify hash
        server_hash = hashlib.sha256(file_content).hexdigest()
        if client_hash != server_hash:
            return jsonify({"error": "File integrity check failed"}), 400
        
        # Secure filename
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({"error": "Invalid filename"}), 400
        
        # Get encryption key
        try:
            key = get_encryption_key(account_number)
            fernet = Fernet(key)
        except FileNotFoundError:
            return jsonify({"error": "Encryption key not found"}), 500
        
        # Encrypt file
        encrypted_content = fernet.encrypt(file_content)
        
        # Save encrypted file
        user_dir = get_user_data_dir(account_number)
        file_path = user_dir / filename
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_content)
        
        logger.info(f"File uploaded: {filename} for account {account_number}")
        
        return jsonify({
            "success": True,
            "message": "File uploaded successfully",
            "filename": filename
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({"error": "Failed to upload file"}), 500


@app.route('/api/download/<filename>', methods=['POST'])
@require_auth
def download_file(account_number, filename):
    """Download a file for the authenticated user."""
    try:
        # Secure filename check
        if not filename or filename == 'encryption.key':
            return jsonify({"error": "Invalid filename"}), 400
        
        filename = secure_filename(filename)
        user_dir = get_user_data_dir(account_number)
        file_path = user_dir / filename
        
        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": "File not found"}), 404
        
        # Get encryption key from request
        data = request.get_json()
        if not data or 'encryption_key' not in data:
            return jsonify({"error": "Encryption key is required"}), 400
        
        try:
            key = data['encryption_key'].encode() if isinstance(data['encryption_key'], str) else data['encryption_key']
            fernet = Fernet(key)
        except Exception as e:
            logger.error(f"Invalid encryption key: {e}")
            return jsonify({"error": "Invalid encryption key"}), 400
        
        # Read and decrypt file
        try:
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
            
            decrypted_content = fernet.decrypt(encrypted_content)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return jsonify({"error": "Decryption failed"}), 500
        
        # Send file
        response = make_response(decrypted_content)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = 'application/octet-stream'
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": "Failed to download file"}), 500


@app.route('/api/download-key', methods=['GET'])
@require_auth
def download_key(account_number):
    """Download the encryption key for the authenticated user."""
    try:
        key_path = get_user_key_path(account_number)
        
        if not key_path.exists():
            return jsonify({"error": "Encryption key not found"}), 404
        
        return send_file(
            str(key_path),
            as_attachment=True,
            download_name='encryption.key',
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        logger.error(f"Error downloading key: {e}")
        return jsonify({"error": "Failed to download encryption key"}), 500


@app.route('/api/delete/<filename>', methods=['DELETE'])
@require_auth
def delete_file(account_number, filename):
    """Delete a file for the authenticated user."""
    try:
        if not filename or filename == 'encryption.key':
            return jsonify({"error": "Invalid filename"}), 400
        
        filename = secure_filename(filename)
        user_dir = get_user_data_dir(account_number)
        file_path = user_dir / filename
        
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        file_path.unlink()
        
        logger.info(f"File deleted: {filename} for account {account_number}")
        
        return jsonify({
            "success": True,
            "message": "File deleted successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({"error": "Failed to delete file"}), 500


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
