"""
Secure Anonymous File Hosting Service
A Flask-based file hosting service with encryption and anonymous account system.
"""

import os
import base64
import secrets
import hashlib
import logging
import re
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


# ---------------------------------------------------------------------------
# Account key helpers
# ---------------------------------------------------------------------------

ACCOUNT_KEY_BYTES = int(os.environ.get('ACCOUNT_KEY_BYTES', '24'))  # 192-bit entropy by default
ACCOUNT_KEY_GROUP_SIZE = int(os.environ.get('ACCOUNT_KEY_GROUP_SIZE', '4'))
ACCOUNT_IDENTIFIER_PREFIX_LEN = int(os.environ.get('ACCOUNT_IDENTIFIER_PREFIX_LEN', '12'))
ACCOUNT_KEY_PATTERN = re.compile(r'^[A-Z2-7]+$')
SESSION_ACCOUNT_ID_KEY = 'account_id'


def _format_account_key_display(normalized_key: str) -> str:
    """Format an uppercase base32 key into grouped chunks for display."""
    chunks = [normalized_key[i:i + ACCOUNT_KEY_GROUP_SIZE] for i in range(0, len(normalized_key), ACCOUNT_KEY_GROUP_SIZE)]
    return '-'.join(chunks)


def generate_account_secret() -> dict:
    """Generate a high-entropy account secret and derived identifiers."""
    raw_bytes = secrets.token_bytes(ACCOUNT_KEY_BYTES)
    # Base32 provides an easy-to-type alphabet (A-Z, 2-7)
    normalized_key = base64.b32encode(raw_bytes).decode('utf-8').rstrip('=')
    display_key = _format_account_key_display(normalized_key)
    account_id = hashlib.sha256(normalized_key.encode('utf-8')).hexdigest()
    fingerprint = account_id[:ACCOUNT_IDENTIFIER_PREFIX_LEN]
    return {
        'normalized_key': normalized_key,
        'display_key': display_key,
        'account_id': account_id,
        'fingerprint': fingerprint
    }


def normalize_account_secret(account_key: str) -> str:
    """Normalize user-supplied account key to canonical uppercase base32."""
    if not account_key:
        raise ValueError("Account key is required")

    stripped = ''.join(ch for ch in account_key.upper() if ch.isalnum())
    if not stripped:
        raise ValueError("Account key is empty after normalization")

    if not ACCOUNT_KEY_PATTERN.fullmatch(stripped):
        raise ValueError("Account key contains invalid characters. Only A-Z and 2-7 are permitted.")

    return stripped


def derive_account_id(normalized_key: str) -> str:
    """Derive the canonical account identifier from a normalized key."""
    return hashlib.sha256(normalized_key.encode('utf-8')).hexdigest()


def format_fingerprint(account_id: str) -> str:
    """Return a short fingerprint for display purposes."""
    return account_id[:ACCOUNT_IDENTIFIER_PREFIX_LEN]


def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        account_id = session.get(SESSION_ACCOUNT_ID_KEY)
        if not account_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # Verify account exists
        try:
            account = db_adapter.find_one(account_id)
            if not account:
                session.clear()
                return jsonify({"error": "Account not found"}), 401
        except Exception as e:
            logger.error(f"Error verifying account: {e}")
            return jsonify({"error": "Authentication failed"}), 500
        
        return f(account_id, *args, **kwargs)
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
        max_attempts = 5
        for _ in range(max_attempts):
            account_bundle = generate_account_secret()
            account_doc = {
                "account_id": account_bundle['account_id'],
                "created_at": datetime.utcnow()
            }

            try:
                db_adapter.insert_one(account_doc)

                logger.info(f"Created account fingerprint={account_bundle['fingerprint']}")

                session.permanent = True
                session[SESSION_ACCOUNT_ID_KEY] = account_bundle['account_id']

                return jsonify({
                    "success": True,
                    "account_key": account_bundle['display_key'],
                    "account_key_compact": account_bundle['normalized_key'],
                    "account_id": account_bundle['account_id'],
                    "account_fingerprint": account_bundle['fingerprint'],
                    "message": "Account created successfully"
                }), 201

            except ValueError as e:
                error_msg = str(e).lower()
                if 'already exists' in error_msg:
                    continue
                raise
            except Exception as e:
                error_msg = str(e).lower()
                error_type = type(e).__name__
                if error_type == 'DuplicateKeyError' or 'duplicate' in error_msg or 'unique' in error_msg:
                    continue
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
        
        try:
            raw_key = data.get('account_key') or data.get('account_number')
            normalized_key = normalize_account_secret(raw_key)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        
        account_id = derive_account_id(normalized_key)

        account = db_adapter.find_one(account_id)
        if not account:
            return jsonify({"error": "Account not found"}), 404
        
        # Set session
        session.permanent = True
        session[SESSION_ACCOUNT_ID_KEY] = account_id
        
        logger.info(f"User logged in fingerprint={format_fingerprint(account_id)}")
        
        return jsonify({
            "success": True,
            "message": "Login successful",
            "account_id": account_id,
            "account_fingerprint": format_fingerprint(account_id)
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
    account_id = session.get(SESSION_ACCOUNT_ID_KEY)
    if not account_id:
        return redirect('/')
    
    # Verify account exists
    account = db_adapter.find_one(account_id)
    if not account:
        session.clear()
        return redirect('/')
    
    return render_template(
        'dashboard.html',
        account_id=account_id,
        account_fingerprint=format_fingerprint(account_id)
    )


@app.route('/api/files', methods=['POST'])
@require_auth
def get_files(account_id):
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
                ownership = db_adapter.find_file_ownership(account_id, file_hash)
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
def upload_file(account_id):
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
                account_id=account_id,
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
def download_file(account_id, file_hash):
    """Download an encrypted file for the authenticated user.
    Returns encrypted file data - decryption happens client-side.
    """
    try:
        # Validate file hash format (64 hex characters for SHA-256)
        if not file_hash or len(file_hash) != 64 or not all(c in '0123456789abcdef' for c in file_hash):
            return jsonify({"error": "Invalid file hash"}), 400
        
        # Verify user owns this file
        ownership = db_adapter.find_file_ownership(account_id, file_hash)
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
def delete_file(account_id, file_hash):
    """Delete file ownership for the authenticated user.
    File is only removed from storage if no other users reference it.
    """
    try:
        # Validate file hash format
        if not file_hash or len(file_hash) != 64 or not all(c in '0123456789abcdef' for c in file_hash):
            return jsonify({"error": "Invalid file hash"}), 400
        
        # Verify user owns this file
        ownership = db_adapter.find_file_ownership(account_id, file_hash)
        if not ownership:
            return jsonify({"error": "File not found"}), 404
        
        # Remove ownership record
        db_adapter.remove_file_ownership(account_id, file_hash)
        
        # Check if any other users reference this file
        other_owners = db_adapter.count_file_owners(file_hash)
        
        # If no other owners, delete the file from storage
        if other_owners == 0:
            file_path = get_file_storage_path(file_hash)
            if file_path.exists():
                file_path.unlink()
                logger.info(f"File removed from storage: {file_hash[:8]}...")
        
        logger.info(f"File ownership deleted for account fingerprint={format_fingerprint(account_id)}")
        
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
