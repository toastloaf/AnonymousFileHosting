# Crypten - Comprehensive Project Analysis

**Analysis Date:** 2025-11-06  
**Project Type:** Secure Anonymous File Hosting Service  
**Stack:** Python Flask + JavaScript + SQLite/MongoDB

---

## Executive Summary

**Crypten** (formerly VaultSphere) is a zero-knowledge, anonymous file hosting service that prioritizes user privacy through client-side encryption and anonymous account management. The service implements a sophisticated architecture where the server never has access to decryption keys, file metadata, or user identities.

### Key Statistics
- **Total Python Code:** ~1,083 lines
- **Frontend Code:** ~2,287 lines (HTML/JS/CSS)
- **Core Files:** 9 code files
- **Main Components:** 19 API endpoints and helper functions
- **Encryption:** AES-256-GCM with PBKDF2 key derivation

---

## Architecture Overview

### 1. **Security Model: Zero-Knowledge Architecture**

The service implements a true zero-knowledge architecture where the server cannot decrypt user data even if compromised:

```
┌─────────────────────────────────────────────────────────┐
│                      CLIENT SIDE                         │
│  • Account Key (192-bit entropy, base32 encoded)        │
│  • PBKDF2 Key Derivation (200,000 iterations)           │
│  • AES-256-GCM Encryption                                │
│  • SHA-256 File Hashing                                  │
│  • Encrypted File Index (localStorage)                  │
└─────────────────────────────────────────────────────────┘
                          ↓ (encrypted data only)
┌─────────────────────────────────────────────────────────┐
│                      SERVER SIDE                         │
│  • Content-Addressable Storage (by hash)                │
│  • Ownership Database (account_id → file_hash)          │
│  • No decryption keys                                    │
│  • No plaintext metadata                                 │
└─────────────────────────────────────────────────────────┘
```

### 2. **Anonymous Account System**

**Inspired by Mullvad VPN**, the service uses a numeric account key system:

- **No Email/Username Required:** Accounts are identified by high-entropy keys
- **Account Key Format:** `AAAA-BBBB-CCCC-DDDD` (base32 encoded, 192-bit entropy)
- **Server Storage:** Only SHA-256 hash of account key (`account_id`)
- **Session Management:** 7-day cookie expiration
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 200,000 iterations

**Security Properties:**
- Brute-force resistant (2^192 possible keys)
- Database compromise doesn't reveal account keys
- No personal information tied to accounts

### 3. **Content-Addressable Storage**

Files are stored by their content hash, not by user ID:

**Storage Structure:**
```
/data/files/
  ├── ab/
  │   └── abc123def456... (SHA-256 hash)
  ├── cd/
  │   └── cde234efg567...
  └── ef/
      └── efg345hij678...
```

**Benefits:**
- **Privacy:** Server compromise doesn't link files to users
- **Deduplication:** Identical files stored once
- **Efficiency:** Sharding by first 2 hash characters improves filesystem performance

### 4. **Client-Side Encryption System**

**Implementation:** `static/js/crypto.js` (277 lines)

```javascript
class ClientCrypto {
  • AES-256-GCM encryption
  • 96-bit IV (nonce)
  • PBKDF2 key derivation
  • Base64 encoding for storage
  • Metadata encryption (filename, size, date)
  • File content encryption
  • localStorage key caching
}
```

**Encryption Flow:**
1. User provides account key
2. Key derived via PBKDF2 (cached in localStorage)
3. File encrypted client-side with random IV
4. Encrypted file + IV sent to server
5. SHA-256 hash computed for storage path
6. Metadata encrypted and stored in local index

---

## Core Components

### Backend (`app.py` - 483 lines)

**Main Features:**

1. **Account Management**
   - `generate_account_secret()`: Creates high-entropy account keys
   - `normalize_account_secret()`: Validates and normalizes user input
   - `derive_account_id()`: SHA-256 hash of account key
   - `create_account()`: POST /api/create-account
   - `login()`: POST /api/login
   - `logout()`: POST /api/logout

2. **File Operations**
   - `upload_file()`: POST /api/upload (with integrity verification)
   - `download_file()`: POST /api/download/<file_hash>
   - `delete_file()`: DELETE /api/delete/<file_hash>
   - `get_files()`: POST /api/files (validates encrypted index)

3. **Security Middleware**
   - `require_auth`: Decorator for authentication
   - Request size limits (5GB max)
   - Hash validation (64 hex chars for SHA-256)
   - Ownership verification before file access

4. **Storage Management**
   - `get_anonymous_storage_dir()`: Central file storage
   - `get_file_storage_path()`: Hash-based paths with sharding
   - Reference counting for safe deletion

### Database Adapter (`db_adapter.py` - 331 lines)

**Dual Database Support:**

```python
class DatabaseAdapter:
  • find_one(account_id)
  • insert_one(account)
  • add_file_ownership(account_id, file_hash, encrypted_metadata, file_size)
  • find_file_ownership(account_id, file_hash)
  • remove_file_ownership(account_id, file_hash)
  • count_file_owners(file_hash)
```

**Implementations:**
- **MongoDBAdapter**: Production-ready with connection pooling
- **SQLiteAdapter**: Local development, file-based storage

**Schema:**

```sql
-- Accounts Table
CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,        -- SHA-256 hash
    created_at TEXT NOT NULL
);

-- File Ownership Table
CREATE TABLE file_ownership (
    account_id TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    encrypted_metadata TEXT NOT NULL,   -- Encrypted blob
    file_size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,
    PRIMARY KEY (account_id, file_hash)
);
```

### Frontend Architecture

#### 1. **Landing Page** (`templates/index.html` - 342 lines)

**Features:**
- Account generation UI
- Login form with base32 validation
- Auto-formatting account key input
- One-click account key copy
- Loading states and animations
- Error/success notifications

**JavaScript Functionality:**
- Account normalization (removes hyphens, validates A-Z, 2-7)
- SessionStorage caching for persistence
- Automatic redirect to dashboard

#### 2. **Dashboard** (`templates/dashboard.html` - 639 lines)

**Sections:**
1. **Header:**
   - Account fingerprint display (first 12 chars of hash)
   - Copy account key button
   - Logout button
   - Statistics cards (total files, storage used, integrity checks)

2. **Upload Section:**
   - File selection with drag & drop UI
   - Client-side encryption before upload
   - Progress bar with percentage
   - Real-time hash computation
   - Metadata encryption

3. **Files Section:**
   - Grid layout of encrypted files
   - Decrypted metadata display (filename, size)
   - Download button (client-side decryption)
   - Delete button (with confirmation)
   - Refresh button

**JavaScript Features:**
- Encryption key initialization from sessionStorage
- Local file index management
- Server validation of file ownership
- Async/await for crypto operations
- XHR for upload progress tracking
- Dynamic file grid rendering

#### 3. **Styling** (`static/css/style.css` - 1,033 lines)

**Design System:**

```css
:root {
  --bg-deep: #020617;              /* Deep space background */
  --accent-primary: #6366f1;       /* Indigo */
  --accent-secondary: #22d3ee;     /* Cyan */
  --accent-tertiary: #f472b6;      /* Pink */
  --radius-lg: 28px;               /* Large radius */
  --transition-snappy: cubic-bezier(0.4, 0, 0.2, 1);
}
```

**Key Features:**
- Modern glassmorphism design
- Gradient backgrounds with blur effects
- Responsive grid layouts
- Dark theme optimized for readability
- Smooth transitions and animations
- Mobile-friendly with breakpoints at 1040px, 900px, 720px, 520px

**Fixed CSS Issues:**
- ✅ Changed `.dashboard-body` from `overflow-x: hidden` to `overflow: hidden`
- **Issue:** Pseudo-elements positioned outside viewport (bottom: -12rem) caused extra scrollable space
- **Solution:** Clipping overflow prevents unwanted scroll at page bottom

---

## Security Analysis

### Threat Model

| Threat | Mitigation | Status |
|--------|------------|--------|
| Server Compromise (Filesystem) | Content-addressable storage, encrypted files | ✅ Protected |
| Server Compromise (Database) | Hashed account IDs, encrypted metadata | ✅ Protected |
| Network Interception | HTTPS required, session cookies | ⚠️ HTTPS needed |
| Brute Force Attacks | 192-bit entropy account keys | ✅ Protected |
| Account Enumeration | Random account generation, no validation | ✅ Protected |
| File Integrity | SHA-256 verification on upload | ✅ Protected |
| Key Extraction | Client-side only, never transmitted | ✅ Protected |

### Security Strengths

1. **Zero-Knowledge Design:**
   - Server never sees decryption keys
   - Encryption happens entirely client-side
   - Even with full server access, files cannot be decrypted

2. **High-Entropy Account Keys:**
   - 192 bits of entropy (2^192 ≈ 6.3 × 10^57 possibilities)
   - Base32 encoding prevents ambiguous characters
   - Formatted for human readability

3. **Content Addressable Storage:**
   - No link between user identity and storage location
   - Automatic deduplication saves space
   - Reference counting prevents premature deletion

4. **Client-Side Metadata Encryption:**
   - Even filenames are encrypted
   - Server stores opaque blobs
   - Full privacy even under server compromise

5. **Integrity Verification:**
   - SHA-256 hash verification on upload
   - Client verifies file integrity
   - Prevents tampering and corruption

### Security Recommendations

1. **HTTPS Enforcement:**
   ```python
   # app.py - Add HTTPS redirect middleware
   @app.before_request
   def force_https():
       if not request.is_secure and os.environ.get('FLASK_ENV') == 'production':
           return redirect(request.url.replace('http://', 'https://'))
   ```

2. **Rate Limiting:**
   - Implement rate limiting for login attempts
   - Prevent account enumeration attacks
   - Use Flask-Limiter or similar

3. **Content Security Policy:**
   ```python
   @app.after_request
   def set_security_headers(response):
       response.headers['Content-Security-Policy'] = "default-src 'self'"
       response.headers['X-Content-Type-Options'] = 'nosniff'
       response.headers['X-Frame-Options'] = 'DENY'
       return response
   ```

4. **Key Backup Mechanism:**
   - Add UI to export encrypted file index
   - Allow users to download backup
   - Import on new device/browser

5. **Session Security:**
   - Already uses HttpOnly cookies ✅
   - Already uses SameSite=Lax ✅
   - Consider SESSION_COOKIE_SECURE in production

---

## Code Quality Assessment

### Strengths

1. **Well-Structured:**
   - Clear separation of concerns
   - Modular design (database adapter pattern)
   - Consistent naming conventions

2. **Documentation:**
   - Comprehensive README.md
   - Detailed SECURITY_ARCHITECTURE.md
   - IMPLEMENTATION_SUMMARY.md with migration guide
   - Inline comments in critical sections

3. **Error Handling:**
   - Try-catch blocks in JavaScript
   - Proper exception handling in Python
   - User-friendly error messages
   - Logging for debugging

4. **Dual Database Support:**
   - Abstract database adapter
   - Easy switching between MongoDB and SQLite
   - Environment variable configuration

5. **Migration Support:**
   - `migrate_to_anonymous_storage.py` script
   - Dry-run mode for testing
   - Automatic backup option

### Areas for Improvement

1. **Testing:**
   - No unit tests present
   - No integration tests
   - Missing test coverage for critical crypto functions

   **Recommendation:**
   ```python
   # tests/test_crypto.py
   import unittest
   class TestCrypto(unittest.TestCase):
       def test_account_generation(self):
           # Test account key generation
       def test_file_encryption(self):
           # Test encryption/decryption
   ```

2. **Type Hints:**
   - Inconsistent type hints in Python code
   - Some functions missing return type annotations

   **Recommendation:**
   ```python
   from typing import Optional, Dict, Any
   
   def generate_account_secret() -> Dict[str, str]:
       # Implementation
   ```

3. **Input Validation:**
   - File upload size limit (5GB) is good
   - Could add file type validation
   - Consider virus scanning integration

4. **Logging:**
   - Basic logging present
   - Could add structured logging
   - Consider log rotation

5. **Performance:**
   - No caching layer
   - Could benefit from Redis for session storage
   - Consider CDN for static assets

---

## Technology Stack

### Backend
- **Framework:** Flask 3.0.0
- **Database:** MongoDB 4.6.0 or SQLite (built-in)
- **Encryption:** cryptography 41.0.7 (not used directly, client-side only)
- **Server:** Werkzeug 3.0.1

### Frontend
- **HTML5:** Semantic markup with ARIA attributes
- **CSS:** Custom styling with Tailwind CSS 3.4.1 foundation
- **JavaScript:** Modern ES6+ with Web Crypto API
- **Fonts:** Inter (UI), JetBrains Mono (monospace keys)

### Crypto
- **Algorithm:** AES-256-GCM
- **Key Derivation:** PBKDF2-HMAC-SHA256 (200k iterations)
- **Hashing:** SHA-256
- **Encoding:** Base32 (account keys), Base64 (storage)

---

## File Structure

```
/workspace/
├── app.py                          # Main Flask application (483 lines)
├── db_adapter.py                   # Database abstraction layer (331 lines)
├── requirements.txt                # Python dependencies
├── README.md                       # User documentation
├── SECURITY_ARCHITECTURE.md        # Security design documentation
├── IMPLEMENTATION_SUMMARY.md       # Implementation details
├── migrate_to_anonymous_storage.py # Migration script
├── plan.txt                        # Original planning notes
├── tailwind.config.js              # Tailwind configuration
│
├── static/
│   ├── css/
│   │   ├── style.css              # Custom styles (1,033 lines)
│   │   └── output.css             # Compiled Tailwind CSS
│   └── js/
│       └── crypto.js              # Client-side encryption (277 lines)
│
└── templates/
    ├── index.html                 # Landing/login page (342 lines)
    └── dashboard.html             # File management dashboard (639 lines)
```

---

## API Endpoints

### Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/create-account` | No | Generate new anonymous account |
| POST | `/api/login` | No | Login with account key |
| POST | `/api/logout` | No | Clear session |

### File Management
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/files` | Yes | Validate encrypted file index |
| POST | `/api/upload` | Yes | Upload encrypted file |
| POST | `/api/download/<hash>` | Yes | Download encrypted file |
| DELETE | `/api/delete/<hash>` | Yes | Delete file and ownership |

### Pages
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing page |
| GET | `/dashboard` | File management dashboard |

---

## Deployment Recommendations

### Environment Variables

```bash
# Flask Configuration
export FLASK_ENV=production
export SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export PORT=5000

# Database (Choose one)
export DATABASE_TYPE=sqlite
export SQLITE_DB_PATH=./data/filehosting.db

# Or MongoDB
export DATABASE_TYPE=mongodb
export MONGO_URI=mongodb://localhost:27017/
export MONGO_DB_NAME=filehosting
export MONGO_COLLECTION_NAME=accounts

# Storage
export DATA_DIR=./data
export MAX_CONTENT_LENGTH=5368709120  # 5GB

# Account System
export ACCOUNT_KEY_BYTES=24              # 192-bit entropy
export ACCOUNT_KEY_GROUP_SIZE=4          # AAAA-BBBB format
export ACCOUNT_IDENTIFIER_PREFIX_LEN=12  # Fingerprint length
```

### Production Checklist

- [ ] Set `FLASK_ENV=production`
- [ ] Generate secure `SECRET_KEY`
- [ ] Enable HTTPS (reverse proxy recommended)
- [ ] Set `SESSION_COOKIE_SECURE=True`
- [ ] Configure backup strategy for database
- [ ] Set up log rotation
- [ ] Implement rate limiting
- [ ] Configure firewall rules
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Regular security audits
- [ ] Database backups
- [ ] File storage backups
- [ ] Document recovery procedures

### Suggested Stack

**Option 1: Simple Deployment**
```
User → Nginx (HTTPS, reverse proxy)
     → Gunicorn (WSGI server)
     → Flask App
     → SQLite database
     → Local file storage
```

**Option 2: Scalable Deployment**
```
User → Cloudflare (CDN, DDoS protection)
     → Nginx (Load balancer)
     → Multiple Gunicorn workers
     → Flask App (multiple instances)
     → MongoDB (replica set)
     → S3-compatible object storage
```

---

## Performance Characteristics

### Storage Efficiency
- **Deduplication:** Automatic, saves storage for duplicate files
- **Sharding:** 256 subdirectories (00-ff) prevent filesystem bottlenecks
- **Compression:** Not implemented (encrypted data doesn't compress well)

### Database Performance
- **MongoDB:** Indexed on `account_id` and `file_hash`
- **SQLite:** Indexed for faster lookups
- **Query Complexity:** O(1) for ownership checks

### Client Performance
- **Encryption:** ~10-50 MB/s depending on device
- **Key Derivation:** ~500ms (PBKDF2 200k iterations)
- **File Hashing:** ~100-200 MB/s (SHA-256 in browser)
- **localStorage:** Fast for file index (<1MB typical)

### Scalability Considerations
- **Horizontal Scaling:** Possible with shared database/storage
- **Session Management:** Currently server-side (needs Redis for scale)
- **File Storage:** Local filesystem limits to single server
  - Consider S3/MinIO for multi-server deployments

---

## Recent Changes (2025-11-06)

### 1. ✅ Renamed Service: VaultSphere → Crypten

**Files Modified:**
- `templates/index.html` (5 occurrences)
- `templates/dashboard.html` (4 occurrences)
- `static/js/crypto.js` (1 occurrence)

**Changes:**
- All branding updated to "Crypten"
- Session storage keys updated: `crypten.session.*`
- KDF salt updated: `crypten_ekdf_v1`

### 2. ✅ Fixed CSS Scrolling Issue

**Problem:**
- Pseudo-elements positioned outside viewport (`bottom: -12rem`)
- Only `overflow-x: hidden` on `.dashboard-body`
- Extra scrollable space at bottom of page

**Solution:**
- Changed `.dashboard-body` overflow from `overflow-x: hidden` to `overflow: hidden`
- Clips decorative pseudo-elements
- Prevents unwanted scroll space
- Maintains internal scrollability

**File Modified:**
- `static/css/style.css` (line 539)

---

## Future Enhancement Ideas

### Short Term (Low Hanging Fruit)

1. **Index Backup/Export**
   - Download encrypted file index as JSON
   - Import on new device
   - Prevents data loss from clearing localStorage

2. **File Sharing**
   - Generate time-limited share links
   - Optional password protection
   - Track download count

3. **Search/Filter**
   - Client-side search in decrypted filenames
   - Filter by file type, size, date
   - Sort options (name, date, size)

4. **Bulk Operations**
   - Select multiple files
   - Bulk download as ZIP (client-side)
   - Bulk delete

5. **Storage Quotas**
   - Track storage per account
   - Display usage statistics
   - Enforce limits

### Medium Term (Moderate Complexity)

1. **Multi-Device Sync**
   - Sync encrypted file index across devices
   - Use account_id as sync anchor
   - E2E encrypted sync protocol

2. **File Versioning**
   - Keep multiple versions of same file
   - Version history UI
   - Restore previous versions

3. **Folder Organization**
   - Client-side folder structure
   - Encrypted folder metadata
   - Breadcrumb navigation

4. **Thumbnail Generation**
   - Client-side thumbnail for images
   - Store encrypted thumbnails
   - Faster preview loading

5. **Progressive Web App (PWA)**
   - Service worker for offline access
   - Add to home screen
   - Push notifications

### Long Term (Complex Features)

1. **Mobile Apps**
   - Native iOS/Android apps
   - Same encryption system
   - Biometric authentication

2. **Collaborative Features**
   - Shared folders between accounts
   - Permission management
   - Activity logs

3. **Advanced Encryption**
   - Support for asymmetric encryption
   - PGP-style key exchange
   - Multiple key management

4. **Audit Logging**
   - Privacy-preserving activity logs
   - Download/upload timestamps
   - Access patterns (without revealing content)

5. **Zero-Knowledge Recovery**
   - Optional key escrow with user passphrase
   - Social recovery (M-of-N keys)
   - Hardware security key support

---

## Comparison with Alternatives

| Feature | Crypten | Nextcloud | SpiderOak | Mega.nz |
|---------|---------|-----------|-----------|---------|
| Client-Side Encryption | ✅ Yes | ⚠️ Optional | ✅ Yes | ✅ Yes |
| Zero-Knowledge | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| Anonymous Accounts | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Open Source | ✅ Yes | ✅ Yes | ❌ No | ⚠️ Partial |
| Self-Hostable | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| Deduplication | ✅ Yes | ⚠️ Limited | ✅ Yes | ✅ Yes |
| File Versioning | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| Mobile Apps | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| Price | Free | Free/Paid | Paid | Free/Paid |

**Unique Selling Points:**
1. True anonymity (no email/username required)
2. Mullvad-style account system
3. Content-addressable storage
4. Zero-knowledge by design (not optional)
5. Simple self-hosting with SQLite

---

## Conclusion

**Crypten** is a well-architected, security-focused file hosting service that successfully implements a zero-knowledge design. The codebase is clean, well-documented, and demonstrates strong security principles.

### Strengths Summary
✅ Strong cryptographic foundation  
✅ True zero-knowledge architecture  
✅ Anonymous account system  
✅ Clean, maintainable code  
✅ Comprehensive documentation  
✅ Dual database support  
✅ Modern, responsive UI  

### Areas for Growth
⚠️ Add automated testing  
⚠️ Implement rate limiting  
⚠️ Add key backup mechanism  
⚠️ Enhance error recovery  
⚠️ Performance optimizations  

### Overall Assessment

**Grade: A- (Excellent with room for polish)**

The project successfully achieves its core goals of privacy and security. With the addition of testing, rate limiting, and some UX improvements (like key backup), this would be production-ready for privacy-conscious users.

---

**Generated by:** Cursor AI Background Agent  
**Analysis Completion Date:** 2025-11-06  
**Project Status:** Active Development  
**Recommendation:** Ready for beta testing with security-aware users
