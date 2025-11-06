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
    }

    /**
     * Generate a random encryption key
     * This key is generated client-side and never sent to the server
     */
    async generateKey() {
        return await crypto.subtle.generateKey(
            this.algorithm,
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Derive a key from account number using PBKDF2
     * This ensures deterministic key generation from account number
     */
    async deriveKeyFromAccount(accountNumber) {
        const accountBytes = new TextEncoder().encode(String(accountNumber));
        
        // Import account number as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            accountBytes,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive key using PBKDF2
        const salt = new TextEncoder().encode('vaultsphere_salt_v1');
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
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
    async storeKey(key, accountNumber) {
        const keyBytes = await this.exportKey(key);
        const keyBase64 = this.uint8ArrayToBase64(keyBytes);
        localStorage.setItem(`encryption_key_${accountNumber}`, keyBase64);
    }

    /**
     * Load encryption key from localStorage
     */
    async loadKey(accountNumber) {
        const keyBase64 = localStorage.getItem(`encryption_key_${accountNumber}`);
        if (!keyBase64) {
            return null;
        }
        const keyBytes = this.base64ToUint8Array(keyBase64);
        return await this.importKey(keyBytes);
    }

    /**
     * Initialize or load encryption key for an account
     * If key doesn't exist, generates a new one and stores it
     */
    async getOrCreateKey(accountNumber) {
        let key = await this.loadKey(accountNumber);
        
        if (!key) {
            // Generate new random key (not derived from account number)
            // This ensures server cannot compute it
            key = await this.generateKey();
            await this.storeKey(key, accountNumber);
        }
        
        return key;
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
