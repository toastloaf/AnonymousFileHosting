/**
 * Client-side encryption utilities using Web Crypto API
 * Ensures decryption keys cannot be computed server-side
 */

class ClientCrypto {
    constructor() {
        this.algorithm = {
            name: 'AES-GCM',
            length: 256
        };
        this.ivLength = 12; // 96 bits for GCM
        this.kdfSalt = new TextEncoder().encode('crypten_ekdf_v1');
        this.kdfIterations = 200000;
    }

    /**
     * Derive a key from the shared account secret using PBKDF2
     * This ensures deterministic key generation across devices.
     */
    async deriveKeyFromAccount(accountSecret) {
        const accountBytes = new TextEncoder().encode(String(accountSecret));
        
        // Import account secret as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            accountBytes,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive key using PBKDF2
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: this.kdfSalt,
                iterations: this.kdfIterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            this.algorithm,
            true, // extractable
            ['encrypt', 'decrypt']
        );

        return derivedKey;
    }

    /**
     * Import a key from raw bytes (for loading from localStorage)
     */
    async importKey(keyBytes) {
        return await crypto.subtle.importKey(
            'raw',
            keyBytes,
            this.algorithm,
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Export a key to raw bytes (for storing in localStorage)
     */
    async exportKey(key) {
        const keyBytes = await crypto.subtle.exportKey('raw', key);
        return new Uint8Array(keyBytes);
    }

    /**
     * Generate a random IV for encryption
     */
    generateIV() {
        return crypto.getRandomValues(new Uint8Array(this.ivLength));
    }

    /**
     * Encrypt data using AES-GCM
     * Returns: { encrypted: Uint8Array, iv: Uint8Array }
     */
    async encrypt(data, key) {
        const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        const iv = this.generateIV();
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.algorithm.name,
                iv: iv
            },
            key,
            dataBytes
        );

        return {
            encrypted: new Uint8Array(encrypted),
            iv: iv
        };
    }

    /**
     * Decrypt data using AES-GCM
     */
    async decrypt(encryptedData, iv, key) {
        const decrypted = await crypto.subtle.decrypt(
            {
                name: this.algorithm.name,
                iv: iv
            },
            key,
            encryptedData
        );

        return new Uint8Array(decrypted);
    }

    /**
     * Encrypt a file (File or Blob)
     * Returns: { encrypted: ArrayBuffer, iv: Uint8Array }
     */
    async encryptFile(file, key) {
        const fileBuffer = await file.arrayBuffer();
        return await this.encrypt(new Uint8Array(fileBuffer), key);
    }

    /**
     * Decrypt a file and return as Blob
     */
    async decryptFile(encryptedData, iv, key, mimeType = 'application/octet-stream') {
        const decrypted = await this.decrypt(encryptedData, iv, key);
        return new Blob([decrypted], { type: mimeType });
    }

    /**
     * Convert Uint8Array to base64 string
     * Uses chunking to handle large arrays
     */
    uint8ArrayToBase64(uint8Array) {
        // Handle large arrays by chunking
        const chunkSize = 0x8000; // 32KB chunks
        let binary = '';
        for (let i = 0; i < uint8Array.length; i += chunkSize) {
            const chunk = uint8Array.subarray(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
    }

    /**
     * Convert base64 string to Uint8Array
     */
    base64ToUint8Array(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Store encryption key in localStorage
     * Key is stored as base64-encoded raw bytes
     */
    async storeKey(key, accountId) {
        const keyBytes = await this.exportKey(key);
        const keyBase64 = this.uint8ArrayToBase64(keyBytes);
        localStorage.setItem(`encryption_key_${accountId}`, keyBase64);
    }

    /**
     * Store encrypted file index in localStorage
     * Index maps file hashes to encrypted metadata (filename, upload date, etc.)
     */
    storeFileIndex(accountId, fileIndex) {
        localStorage.setItem(`file_index_${accountId}`, JSON.stringify(fileIndex));
    }

    /**
     * Load encrypted file index from localStorage
     */
    loadFileIndex(accountId) {
        const indexJson = localStorage.getItem(`file_index_${accountId}`);
        return indexJson ? JSON.parse(indexJson) : [];
    }

    /**
     * Load encryption key from localStorage
     */
    async loadKey(accountId) {
        const keyBase64 = localStorage.getItem(`encryption_key_${accountId}`);
        if (!keyBase64) {
            return null;
        }
        const keyBytes = this.base64ToUint8Array(keyBase64);
        return await this.importKey(keyBytes);
    }

    /**
     * Load the cached encryption key or derive it deterministically.
     */
    async getKeyForAccount(accountId, accountSecret) {
        let key = await this.loadKey(accountId);

        if (key) {
            return key;
        }

        if (!accountSecret) {
            return null;
        }

        const derived = await this.deriveKeyFromAccount(accountSecret);
        await this.storeKey(derived, accountId);
        return derived;
    }

    /**
     * Encrypt filename (for metadata encryption)
     */
    async encryptFilename(filename, key) {
        const filenameBytes = new TextEncoder().encode(filename);
        const result = await this.encrypt(filenameBytes, key);
        
        // Combine IV and encrypted data for storage
        const combined = new Uint8Array(result.iv.length + result.encrypted.length);
        combined.set(result.iv, 0);
        combined.set(result.encrypted, result.iv.length);
        
        return this.uint8ArrayToBase64(combined);
    }

    /**
     * Encrypt file metadata (filename, original size, upload date)
     */
    async encryptMetadata(metadata, key) {
        const metadataJson = JSON.stringify(metadata);
        const metadataBytes = new TextEncoder().encode(metadataJson);
        const result = await this.encrypt(metadataBytes, key);
        
        // Combine IV and encrypted data
        const combined = new Uint8Array(result.iv.length + result.encrypted.length);
        combined.set(result.iv, 0);
        combined.set(result.encrypted, result.iv.length);
        
        return this.uint8ArrayToBase64(combined);
    }

    /**
     * Decrypt file metadata
     */
    async decryptMetadata(encryptedMetadataBase64, key) {
        const combined = this.base64ToUint8Array(encryptedMetadataBase64);
        const iv = combined.slice(0, this.ivLength);
        const encrypted = combined.slice(this.ivLength);
        
        const decrypted = await this.decrypt(encrypted, iv, key);
        const metadataJson = new TextDecoder().decode(decrypted);
        return JSON.parse(metadataJson);
    }

    /**
     * Decrypt filename
     */
    async decryptFilename(encryptedFilenameBase64, key) {
        const combined = this.base64ToUint8Array(encryptedFilenameBase64);
        const iv = combined.slice(0, this.ivLength);
        const encrypted = combined.slice(this.ivLength);
        
        const decrypted = await this.decrypt(encrypted, iv, key);
        return new TextDecoder().decode(decrypted);
    }
}

// Export singleton instance
const clientCrypto = new ClientCrypto();
