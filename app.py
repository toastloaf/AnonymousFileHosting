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
from urllib.parse import quote
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.http import quote_header_value
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from db_adapter import create_database_adapter

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

# Data directory
DATA_DIR = Path(os.environ.get('DATA_DIR', './data'))
DATA_DIR.mkdir(exist_ok=True)

# Initialize database adapter (MongoDB or SQLite)
try:
    db_adapter = create_database_adapter()
    logger.info(f"Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
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
            account = db_adapter.find_one(account_number)
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


def derive_encryption_key(account_number):
    """Derive encryption key from account number using PBKDF2."""
    # Convert account number to bytes
    account_bytes = str(account_number).encode('utf-8')
    
    # Use PBKDF2 to derive a 32-byte key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'secure_file_hosting_salt',  # Fixed salt for deterministic key derivation
        iterations=100000,
        backend=default_backend()
    )
    
    # Derive key and encode as base64 for Fernet
    key = base64.urlsafe_b64encode(kdf.derive(account_bytes))
    return key


def get_user_fernet(account_number):
    """Get a Fernet instance for the specified account."""
    key = derive_encryption_key(account_number)
    return Fernet(key)


def is_valid_plain_filename(filename):
    """Validate that a filename is safe to use without altering user-provided characters."""
    if not isinstance(filename, str):
        return False
    if filename.strip() == '':
        return False
    if filename in {'.', '..'}:
        return False
    if '\x00' in filename:
        return False
    if '/' in filename or '\\' in filename:
        return False
    return True


def build_content_disposition(filename):
    """Build a Content-Disposition header value that preserves the original filename."""
    disposition = f"attachment; filename={quote_header_value(filename)}"
    try:
        filename.encode('ascii')
    except UnicodeEncodeError:
        disposition += f"; filename*=UTF-8''{quote(filename)}"
    return disposition


def encrypt_filename(filename, fernet):
    """Encrypt a filename using the provided Fernet instance."""
    return fernet.encrypt(filename.encode('utf-8')).decode('utf-8')


def decrypt_filename(encrypted_filename, fernet):
    """Decrypt an encrypted filename using the provided Fernet instance."""
    return fernet.decrypt(encrypted_filename.encode('utf-8')).decode('utf-8')


def resolve_user_file_path(user_dir, target_filename, fernet):
    """Resolve the filesystem path for a user's file by its plaintext filename."""
    for file_path in user_dir.iterdir():
        if not file_path.is_file():
            continue

        try:
            decrypted_name = decrypt_filename(file_path.name, fernet)
            if decrypted_name == target_filename:
                return file_path
        except InvalidToken:
            if file_path.name == target_filename:
                return file_path

    return None


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
                db_adapter.insert_one(doc)
                
                # Key is derived from account number, no need to generate/store separately
                logger.info(f"Created account: {account_number}")
                
                # Set session
                session.permanent = True
                session['account_number'] = account_number
                
                return jsonify({
                    "success": True,
                    "account_number": account_number,
                    "message": "Account created successfully"
                }), 201
                
            except ValueError as e:
                # SQLite raises ValueError for duplicate keys
                error_msg = str(e).lower()
                if 'already exists' in error_msg:
                    # Account number collision, try again
                    continue
                else:
                    # Some other ValueError, re-raise it
                    raise
            except Exception as e:
                # MongoDB raises DuplicateKeyError (which is an Exception)
                # Check if it's a duplicate key error
                error_type = type(e).__name__
                error_msg = str(e).lower()
                if error_type == 'DuplicateKeyError' or 'duplicate' in error_msg or 'unique' in error_msg:
                    # Account number collision, try again
                    continue
                else:
                    # Some other error, re-raise it
                    raise
        
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
        account = db_adapter.find_one(account_number)
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
    account = db_adapter.find_one(account_number)
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
        fernet = get_user_fernet(account_number)
        files = []
        
        for file_path in user_dir.iterdir():
            if file_path.is_file():
                size_bytes = file_path.stat().st_size
                size_mb = round(size_bytes / (1024 * 1024), 2)

                try:
                    original_name = decrypt_filename(file_path.name, fernet)
                except InvalidToken:
                    original_name = file_path.name
                
                files.append({
                    'name': original_name,
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
        
        original_filename = file.filename
        if not is_valid_plain_filename(original_filename):
            return jsonify({"error": "Invalid filename"}), 400
        filename = original_filename
        
        # Derive encryption key from account number
        fernet = get_user_fernet(account_number)
        
        # Encrypt file
        encrypted_content = fernet.encrypt(file_content)
        
        # Save encrypted file
        user_dir = get_user_data_dir(account_number)

        # Remove any existing file with the same plaintext name
        existing_path = resolve_user_file_path(user_dir, filename, fernet)
        if existing_path and existing_path.exists():
            existing_path.unlink()

        # Encrypt filename for storage and ensure uniqueness
        attempt = 0
        while True:
            encrypted_filename = encrypt_filename(filename, fernet)
            file_path = user_dir / encrypted_filename
            if not file_path.exists():
                break
            attempt += 1
            if attempt > 5:
                logger.error("Failed to find unique encrypted filename")
                return jsonify({"error": "Failed to process file"}), 500
        
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
        if not is_valid_plain_filename(filename):
            return jsonify({"error": "Invalid filename"}), 400
        user_dir = get_user_data_dir(account_number)
        fernet = get_user_fernet(account_number)

        file_path = resolve_user_file_path(user_dir, filename, fernet)

        if not file_path or not file_path.exists() or not file_path.is_file():
            return jsonify({"error": "File not found"}), 404
        
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
        response.headers['Content-Disposition'] = build_content_disposition(filename)
        response.headers['Content-Type'] = 'application/octet-stream'
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": "Failed to download file"}), 500




@app.route('/api/delete/<filename>', methods=['DELETE'])
@require_auth
def delete_file(account_number, filename):
    """Delete a file for the authenticated user."""
    try:
        if not is_valid_plain_filename(filename):
            return jsonify({"error": "Invalid filename"}), 400
        user_dir = get_user_data_dir(account_number)
        fernet = get_user_fernet(account_number)

        file_path = resolve_user_file_path(user_dir, filename, fernet)

        if not file_path or not file_path.exists():
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
