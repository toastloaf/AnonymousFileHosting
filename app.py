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

from flask import Flask, jsonify, render_template, request, make_response, session, redirect
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


def get_anonymous_storage_dir():
    """Get the anonymous storage directory for all files.
    Files are stored by content hash, not user ID, for security.
    """
    storage_dir = DATA_DIR / 'files'
    storage_dir.mkdir(exist_ok=True)
    return storage_dir


def get_file_storage_path(file_hash):
    """Get storage path for a file based on its content hash.
    Uses sharding for better filesystem performance.
    """
    storage_dir = get_anonymous_storage_dir()
    # Use first 2 characters of hash for sharding
    shard_dir = storage_dir / file_hash[:2]
    shard_dir.mkdir(exist_ok=True)
    return shard_dir / file_hash




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


@app.route('/api/files', methods=['POST'])
@require_auth
def get_files(account_number):
    """Get list of files for the authenticated user.
    Client sends encrypted file index, server validates ownership and returns file metadata.
    """
    try:
        data = request.get_json()
        if not data or 'encrypted_file_index' not in data:
            return jsonify({"error": "Encrypted file index required"}), 400
        
        encrypted_index = data['encrypted_file_index']
        
        # encrypted_index is a list of {file_hash, encrypted_metadata}
        # Server validates that these files exist and returns their current sizes
        validated_files = []
        
        for file_entry in encrypted_index:
            file_hash = file_entry.get('file_hash')
            if not file_hash:
                continue
                
            # Verify file exists in storage
            file_path = get_file_storage_path(file_hash)
            if file_path.exists() and file_path.is_file():
                # Verify ownership in database
                ownership = db_adapter.find_file_ownership(account_number, file_hash)
                if ownership:
                    size_bytes = file_path.stat().st_size
                    validated_files.append({
                        'file_hash': file_hash,
                        'encrypted_metadata': file_entry.get('encrypted_metadata', ''),
                        'size_bytes': size_bytes
                    })
        
        return jsonify({"success": True, "files": validated_files}), 200
        
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({"error": "Failed to retrieve files"}), 500


@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file(account_number):
    """Upload an encrypted file for the authenticated user.
    Files are stored anonymously by content hash, not by user ID.
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Get client-side hash of encrypted data
        client_hash = request.form.get('file_hash')
        if not client_hash:
            return jsonify({"error": "File hash is required"}), 400
        
        # Get encrypted metadata from client (filename, etc.)
        encrypted_metadata = request.form.get('encrypted_metadata')
        if not encrypted_metadata:
            return jsonify({"error": "Encrypted metadata is required"}), 400
        
        # Read encrypted file content (already encrypted client-side)
        encrypted_content = file.read()
        
        # Verify hash of encrypted data
        server_hash = hashlib.sha256(encrypted_content).hexdigest()
        if client_hash != server_hash:
            return jsonify({"error": "File integrity check failed"}), 400
        
        # Store file anonymously by content hash
        file_path = get_file_storage_path(server_hash)
        
        # Check if file already exists (deduplication)
        file_already_exists = file_path.exists()
        
        if not file_already_exists:
            # Write encrypted content to anonymous storage
            with open(file_path, 'wb') as f:
                f.write(encrypted_content)
        
        # Record ownership in database (encrypted metadata stored)
        try:
            db_adapter.add_file_ownership(
                account_number=account_number,
                file_hash=server_hash,
                encrypted_metadata=encrypted_metadata,
                file_size=len(encrypted_content)
            )
        except Exception as e:
            # If ownership record fails and file is new, clean up
            if not file_already_exists:
                file_path.unlink()
            raise e
        
        logger.info(f"File uploaded: hash={server_hash[:8]}..., dedup={file_already_exists}")
        
        return jsonify({
            "success": True,
            "message": "File uploaded successfully",
            "file_hash": server_hash
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({"error": "Failed to upload file"}), 500


@app.route('/api/download/<path:file_hash>', methods=['POST'])
@require_auth
def download_file(account_number, file_hash):
    """Download an encrypted file for the authenticated user.
    Returns encrypted file data - decryption happens client-side.
    """
    try:
        # Validate file hash format (64 hex characters for SHA-256)
        if not file_hash or len(file_hash) != 64 or not all(c in '0123456789abcdef' for c in file_hash):
            return jsonify({"error": "Invalid file hash"}), 400
        
        # Verify user owns this file
        ownership = db_adapter.find_file_ownership(account_number, file_hash)
        if not ownership:
            return jsonify({"error": "File not found or access denied"}), 404
        
        # Get file from anonymous storage
        file_path = get_file_storage_path(file_hash)
        
        if not file_path.exists() or not file_path.is_file():
            # File ownership exists but file is missing - data integrity issue
            logger.error(f"File missing from storage: {file_hash}")
            return jsonify({"error": "File data not found"}), 404
        
        # Read encrypted file (no server-side decryption)
        try:
            with open(file_path, 'rb') as f:
                encrypted_content = f.read()
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            return jsonify({"error": "Failed to read file"}), 500
        
        # Send encrypted file as-is (client will decrypt)
        response = make_response(encrypted_content)
        response.headers['Content-Type'] = 'application/octet-stream'
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": "Failed to download file"}), 500




@app.route('/api/delete/<path:file_hash>', methods=['DELETE'])
@require_auth
def delete_file(account_number, file_hash):
    """Delete file ownership for the authenticated user.
    File is only removed from storage if no other users reference it.
    """
    try:
        # Validate file hash format
        if not file_hash or len(file_hash) != 64 or not all(c in '0123456789abcdef' for c in file_hash):
            return jsonify({"error": "Invalid file hash"}), 400
        
        # Verify user owns this file
        ownership = db_adapter.find_file_ownership(account_number, file_hash)
        if not ownership:
            return jsonify({"error": "File not found"}), 404
        
        # Remove ownership record
        db_adapter.remove_file_ownership(account_number, file_hash)
        
        # Check if any other users reference this file
        other_owners = db_adapter.count_file_owners(file_hash)
        
        # If no other owners, delete the file from storage
        if other_owners == 0:
            file_path = get_file_storage_path(file_hash)
            if file_path.exists():
                file_path.unlink()
                logger.info(f"File removed from storage: {file_hash[:8]}...")
        
        logger.info(f"File ownership deleted for account {account_number}")
        
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
