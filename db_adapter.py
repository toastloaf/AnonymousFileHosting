"""
Database adapter for MongoDB and SQLite support.
Provides a unified interface for database operations.
"""

import os
import sqlite3
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseAdapter:
    """Base class for database adapters."""
    
    def find_one(self, account_number: int) -> Optional[Dict[str, Any]]:
        """Find an account by account number."""
        raise NotImplementedError
    
    def insert_one(self, account: Dict[str, Any]) -> None:
        """Insert a new account."""
        raise NotImplementedError
    
    def initialize(self) -> None:
        """Initialize the database connection and tables."""
        raise NotImplementedError


class MongoDBAdapter(DatabaseAdapter):
    """MongoDB database adapter."""
    
    def __init__(self, mongo_uri: str, db_name: str, collection_name: str):
        import pymongo
        from pymongo.errors import ConnectionFailure
        
        self.mongo_uri = mongo_uri
        self.db_name = db_name
        self.collection_name = collection_name
        self.pymongo = pymongo
        self.ConnectionFailure = ConnectionFailure
        
    def initialize(self) -> None:
        """Initialize MongoDB connection."""
        try:
            self.client = self.pymongo.MongoClient(
                self.mongo_uri,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=50
            )
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            # Create index on account number for faster lookups
            self.collection.create_index("account_number", unique=True)
            logger.info("Connected to MongoDB successfully")
        except self.ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    def find_one(self, account_number: int) -> Optional[Dict[str, Any]]:
        """Find an account by account number."""
        return self.collection.find_one({"account_number": account_number})
    
    def insert_one(self, account: Dict[str, Any]) -> None:
        """Insert a new account."""
        from pymongo.errors import DuplicateKeyError
        self.collection.insert_one(account)


class SQLiteAdapter(DatabaseAdapter):
    """SQLite database adapter."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
    
    def initialize(self) -> None:
        """Initialize SQLite database and create tables."""
        try:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row  # Enable column access by name
            
            # Create accounts table if it doesn't exist
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    account_number INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Create unique index on account_number
            cursor.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS idx_account_number 
                ON accounts(account_number)
            ''')
            
            self.conn.commit()
            logger.info(f"Connected to SQLite database successfully: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to SQLite database: {e}")
            raise
    
    def find_one(self, account_number: int) -> Optional[Dict[str, Any]]:
        """Find an account by account number."""
        if not self.conn:
            raise RuntimeError("Database not initialized")
        
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT account_number, created_at FROM accounts WHERE account_number = ?',
            (account_number,)
        )
        row = cursor.fetchone()
        
        if row:
            return {
                'account_number': row['account_number'],
                'created_at': row['created_at']
            }
        return None
    
    def insert_one(self, account: Dict[str, Any]) -> None:
        """Insert a new account."""
        if not self.conn:
            raise RuntimeError("Database not initialized")
        
        import sqlite3
        
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO accounts (account_number, created_at) VALUES (?, ?)',
                (account['account_number'], account['created_at'].isoformat())
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            # Duplicate key error (account number already exists)
            self.conn.rollback()
            raise ValueError("Account number already exists")
    
    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()


def create_database_adapter() -> DatabaseAdapter:
    """Create and initialize the appropriate database adapter based on configuration."""
    database_type = os.environ.get('DATABASE_TYPE', 'mongodb').lower()
    
    if database_type == 'sqlite':
        db_path = os.environ.get('SQLITE_DB_PATH', './data/filehosting.db')
        adapter = SQLiteAdapter(db_path)
        adapter.initialize()
        return adapter
    elif database_type == 'mongodb':
        mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
        db_name = os.environ.get('MONGO_DB_NAME', 'filehosting')
        collection_name = os.environ.get('MONGO_COLLECTION_NAME', 'accounts')
        adapter = MongoDBAdapter(mongo_uri, db_name, collection_name)
        adapter.initialize()
        return adapter
    else:
        raise ValueError(f"Unsupported database type: {database_type}. Use 'mongodb' or 'sqlite'")
