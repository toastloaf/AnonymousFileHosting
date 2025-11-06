# Security Architecture - Anonymous Content-Addressable Storage

## Overview

This document describes the enhanced security architecture that eliminates the direct mapping between user accounts and their files on the server.

## Problem Statement

**Previous Architecture:**
- Files were stored in folders named after user account numbers (e.g., `/data/1234567890/`)
- If the server was compromised, an attacker could immediately:
  - Identify which files belong to which user
  - Correlate file sizes, upload times, and access patterns to specific accounts
  - Even though files were encrypted, the metadata association was leaked

## Solution: Anonymous Content-Addressable Storage

### Key Changes

1. **Content-Addressable Storage**
   - Files are stored by their SHA-256 hash, not by user ID
   - Storage path: `/data/files/{first_2_chars_of_hash}/{full_hash}`
   - Example: A file with hash `abc123...` is stored at `/data/files/ab/abc123...`
   - This provides automatic deduplication (same file uploaded by multiple users = one copy)

2. **Client-Side Encrypted File Index**
   - Each user maintains an encrypted index in their browser's localStorage
   - Index maps file hashes to encrypted metadata (filename, size, upload date)
   - Server never sees or stores this mapping - it only validates ownership

3. **Encrypted Metadata**
   - Instead of encrypted filenames, we now use encrypted metadata blobs
   - Metadata includes: original filename, original size, upload timestamp
   - Encrypted using AES-GCM with the user's encryption key

4. **Database-Backed Ownership**
   - New `file_ownership` table tracks which accounts can access which file hashes
   - Even if the database is compromised, the attacker only sees hashes, not filenames
   - File reference counting enables safe deletion (file removed only when no users reference it)

## Security Properties

### Server Compromise Scenarios

**Scenario 1: Filesystem Only Compromised**
- Attacker sees: Encrypted file blobs named by hash
- Attacker cannot: 
  - Determine which user owns which file
  - Determine original filenames
  - Decrypt file contents (keys are client-side only)

**Scenario 2: Database Only Compromised**
- Attacker sees: Account numbers and file hashes they own
- Attacker cannot:
  - Access the actual file data
  - Determine original filenames (metadata is encrypted)
  - Decrypt file contents

**Scenario 3: Full Server Compromise (Filesystem + Database)**
- Attacker sees: Account → Hash mappings, encrypted file blobs
- Attacker cannot:
  - Decrypt file contents (encryption keys never leave client)
  - Determine original filenames (metadata is client-side encrypted)
  - Link files to real identities (account numbers are anonymous)

### Key Security Benefits

1. **Separation of Identity and Storage**
   - No direct mapping between account numbers and file storage locations
   - Account compromise doesn't reveal storage locations
   - Storage location knowledge doesn't reveal ownership

2. **Client-Side Key Management**
   - Encryption keys generated randomly in browser
   - Stored only in localStorage, never transmitted to server
   - Server cannot compute or derive user keys

3. **Encrypted Metadata**
   - Even metadata like filenames are encrypted client-side
   - Server stores opaque encrypted blobs
   - Only the user can decrypt their file index

4. **Automatic Deduplication**
   - Content-addressable storage naturally deduplicates
   - Saves server storage space
   - Privacy-preserving (server can't tell if two users uploaded same file)

5. **Forward Secrecy**
   - If a user clears their localStorage, their file index is lost
   - Even the server cannot help recover the file list
   - This is a feature: true zero-knowledge architecture

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT SIDE                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌─────────────────────────────┐ │
│  │ Encryption Key   │      │   Encrypted File Index      │ │
│  │ (AES-256-GCM)    │      │   [{hash, enc_metadata}]    │ │
│  │  localStorage    │      │      localStorage           │ │
│  └──────────────────┘      └─────────────────────────────┘ │
│           │                            │                     │
│           ▼                            ▼                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │     Client encrypts files & metadata before upload     │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
└──────────────────────────────┼───────────────────────────────┘
                               │
                               ▼  (Encrypted data + hash)
┌─────────────────────────────────────────────────────────────┐
│                         SERVER SIDE                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Content-Addressable Storage                ││
│  │         /data/files/{shard}/{file_hash}                 ││
│  │  (Encrypted blobs, no user association)                 ││
│  └─────────────────────────────────────────────────────────┘│
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                 file_ownership Table                     ││
│  │  ┌────────────┬───────────┬──────────────────────────┐  ││
│  │  │ account_no │ file_hash │ encrypted_metadata       │  ││
│  │  ├────────────┼───────────┼──────────────────────────┤  ││
│  │  │ 123456     │ abc123... │ ew4r5t6y7u8i9o0p...      │  ││
│  │  │ 789012     │ def456... │ q2w3e4r5t6y7u8i9...      │  ││
│  │  └────────────┴───────────┴──────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────┘│
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## API Changes

### Upload Flow

**Before:**
```
Client → Encrypt file → Upload with encrypted_filename → 
Server stores at /data/{account_number}/{encrypted_filename}
```

**After:**
```
Client → Encrypt file → Generate hash → Encrypt metadata →
Upload with hash & encrypted_metadata → 
Server stores at /data/files/{hash[:2]}/{hash} →
Server records ownership in database →
Client updates local file index
```

### Download Flow

**Before:**
```
Client requests encrypted_filename →
Server reads from /data/{account_number}/{encrypted_filename} →
Returns encrypted data → Client decrypts
```

**After:**
```
Client looks up hash from local index →
Client requests hash →
Server validates ownership in database →
Server reads from /data/files/{hash[:2]}/{hash} →
Returns encrypted data → Client decrypts
```

### Delete Flow

**Before:**
```
Client requests delete encrypted_filename →
Server deletes /data/{account_number}/{encrypted_filename}
```

**After:**
```
Client requests delete hash →
Server removes ownership record →
Server counts remaining owners →
If no other owners: Server deletes physical file →
Client removes from local index
```

## Migration from Old Architecture

For existing deployments using user-ID-based folders:

1. Files in old location: `/data/{account_number}/{encrypted_filename}`
2. Create migration script to:
   - Read all files from user directories
   - Compute SHA-256 hash of encrypted content
   - Move files to new location: `/data/files/{hash[:2]}/{hash}`
   - Create ownership records in database
   - Generate encrypted metadata for each file
   - Clean up old user directories

3. Users will need to:
   - Clear their localStorage (old file indexes)
   - Re-scan their files on server
   - Build new encrypted file index

## Best Practices

1. **Regular Index Backups**
   - Users should periodically export their file index
   - Provide UI to download encrypted index as backup
   - Index can be imported on new device/browser

2. **Key Management**
   - Warn users when clearing browser data
   - Provide key export/import functionality
   - Consider optional key recovery mechanism (user's choice)

3. **Server Hardening**
   - Even with this architecture, standard security practices apply
   - Regular security updates
   - Principle of least privilege
   - Monitoring and logging

4. **Deduplication Awareness**
   - Content-addressable storage enables deduplication
   - Privacy implication: timing attacks could reveal common files
   - Mitigation: Add random delay to upload responses

## Conclusion

This architecture provides defense-in-depth security where even a complete server compromise reveals minimal information about users and their files. The zero-knowledge design ensures that encryption keys and file metadata never leave the client, making it cryptographically impossible for the server to access user data.
