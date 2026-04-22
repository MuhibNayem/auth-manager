"""
Migration Tools - Import users from external authentication providers

Supports: Firebase, Auth0, Django, Cognito, Supabase
Features: Lazy password migration, hash translation, dry-run mode
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Generator
from datetime import datetime


class BaseImporter(ABC):
    """Base class for all authentication providers importers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.stats = {
            'total': 0,
            'migrated': 0,
            'failed': 0,
            'skipped': 0
        }
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to source provider"""
        pass
    
    @abstractmethod
    async def fetch_users(self, batch_size: int = 100) -> Generator[List[Dict], None, None]:
        """Fetch users in batches from source provider"""
        pass
    
    @abstractmethod
    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Translate password hash to Authy format"""
        pass
    
    def preview_migration(self) -> Dict[str, Any]:
        """Preview migration without applying changes"""
        return {
            'provider': self.__class__.__name__,
            'estimated_users': 'Unknown (connect to preview)',
            'warnings': [],
            'strategy': 'lazy-password-migration'
        }
    
    async def migrate(self, strategy: str = 'lazy-password-migration') -> Dict[str, Any]:
        """Execute user migration"""
        await self.connect()
        
        results = {
            'count': 0,
            'warnings': [],
            'errors': []
        }
        
        try:
            async for user_batch in self.fetch_users():
                for user_data in user_batch:
                    try:
                        migrated_user = await self._migrate_user(user_data, strategy)
                        if migrated_user:
                            results['count'] += 1
                            self.stats['migrated'] += 1
                    except Exception as e:
                        results['errors'].append({
                            'user_id': user_data.get('id', 'unknown'),
                            'error': str(e)
                        })
                        self.stats['failed'] += 1
                
                self.stats['total'] += len(user_batch)
                
        except Exception as e:
            results['errors'].append({'error': f'Migration failed: {str(e)}'})
        
        return results
    
    async def _migrate_user(self, user_data: Dict[str, Any], strategy: str) -> Optional[Dict]:
        """Migrate single user"""
        from ..db import get_database
        
        db = await get_database()
        
        # Check if user exists
        existing = await db.users.find_one({'email': user_data['email']})
        if existing:
            self.stats['skipped'] += 1
            return None
        
        # Prepare user data
        authy_user = {
            'email': user_data['email'],
            'email_verified': user_data.get('email_verified', False),
            'created_at': user_data.get('created_at', datetime.utcnow()),
            'updated_at': datetime.utcnow(),
            'external_provider': self.__class__.__name__,
            'external_id': user_data.get('id')
        }
        
        # Handle password based on strategy
        if 'password_hash' in user_data and strategy == 'full':
            translated_hash = self.translate_password_hash(
                user_data['password_hash'],
                user_data.get('password_algorithm', 'unknown')
            )
            if translated_hash:
                authy_user['password_hash'] = translated_hash
                authy_user['password_needs_rehash'] = True
            else:
                authy_user['password_reset_required'] = True
        elif strategy == 'lazy-password-migration':
            # Store original hash for lazy migration on first login
            if 'password_hash' in user_data:
                authy_user['legacy_password_hash'] = {
                    'hash': user_data['password_hash'],
                    'algorithm': user_data.get('password_algorithm', 'unknown'),
                    'provider': self.__class__.__name__
                }
        
        # Insert user
        result = await db.users.insert_one(authy_user)
        authy_user['id'] = str(result.inserted_id)
        
        return authy_user


class FirebaseImporter(BaseImporter):
    """Import users from Firebase Authentication"""
    
    async def connect(self) -> None:
        """Connect to Firebase Admin SDK"""
        try:
            import firebase_admin
            from firebase_admin import credentials, auth
            
            if not firebase_admin._apps:
                cred_path = self.config.get('service_account_file')
                if cred_path:
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(cred)
                else:
                    # Use default credentials
                    firebase_admin.initialize_app()
            
            self.firebase_auth = auth
            print("✅ Connected to Firebase")
            
        except ImportError:
            raise ImportError("Install firebase-admin: pip install firebase-admin")
    
    async def fetch_users(self, batch_size: int = 100) -> Generator[List[Dict], None, None]:
        """Fetch users from Firebase"""
        page_token = None
        
        while True:
            users_page = self.firebase_auth.list_users(page_token=page_token, max_results=batch_size)
            
            batch = []
            for user in users_page.users:
                user_data = {
                    'id': user.uid,
                    'email': user.email,
                    'email_verified': user.email_verified,
                    'created_at': datetime.fromtimestamp(user.user_metadata.creation_timestamp / 1000),
                    'password_hash': user.password_hash if hasattr(user, 'password_hash') else None,
                    'password_algorithm': user.password_hash_algorithm if hasattr(user, 'password_hash_algorithm') else None,
                    'display_name': user.display_name,
                    'photo_url': user.photo_url
                }
                batch.append(user_data)
            
            if batch:
                yield batch
            
            if not users_page.page_token:
                break
            
            page_token = users_page.page_token
    
    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Translate Firebase password hash to Authy format"""
        # Firebase uses various algorithms: SCRYPT, BCRYPT, PBKDF2, etc.
        # For lazy migration, we store the original hash and re-hash on first login
        if algorithm in ['BCRYPT', 'bcrypt']:
            return hash_str  # bcrypt is compatible
        elif algorithm in ['SCRYPT', 'scrypt']:
            # Store for lazy migration
            return None
        else:
            # Unknown algorithm, force password reset
            return None
    
    def preview_migration(self) -> Dict[str, Any]:
        """Preview Firebase migration"""
        try:
            asyncio.run(self.connect())
            count = 0
            for _ in asyncio.run(self.fetch_users().__anext__()):
                count += 1
            return {
                'provider': 'Firebase',
                'estimated_users': f'{count}+ (first batch)',
                'warnings': [
                    'Password hashes may require lazy migration',
                    'Custom claims will not be migrated automatically'
                ],
                'strategy': 'lazy-password-migration'
            }
        except Exception as e:
            return {
                'provider': 'Firebase',
                'estimated_users': 'Unknown',
                'warnings': [f'Connection error: {str(e)}'],
                'strategy': 'lazy-password-migration'
            }


class Auth0Importer(BaseImporter):
    """Import users from Auth0"""
    
    async def connect(self) -> None:
        """Connect to Auth0 Management API"""
        import aiohttp
        
        self.domain = self.config.get('domain')
        self.client_id = self.config.get('client_id')
        self.client_secret = self.config.get('client_secret')
        
        # Get access token
        async with aiohttp.ClientSession() as session:
            token_url = f'https://{self.domain}/oauth/token'
            payload = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': f'https://{self.domain}/api/v2/'
            }
            
            async with session.post(token_url, json=payload) as resp:
                if resp.status != 200:
                    raise Exception(f'Auth0 token request failed: {await resp.text()}')
                
                token_data = await resp.json()
                self.access_token = token_data['access_token']
        
        print("✅ Connected to Auth0")
    
    async def fetch_users(self, batch_size: int = 100) -> Generator[List[Dict], None, None]:
        """Fetch users from Auth0 Management API"""
        import aiohttp
        
        headers = {'Authorization': f'Bearer {self.access_token}'}
        page = 0
        
        async with aiohttp.ClientSession() as session:
            while True:
                url = f'https://{self.domain}/api/v2/users'
                params = {
                    'per_page': batch_size,
                    'page': page,
                    'include_totals': 'false'
                }
                
                async with session.get(url, headers=headers, params=params) as resp:
                    if resp.status != 200:
                        raise Exception(f'Auth0 user fetch failed: {await resp.text()}')
                    
                    users = await resp.json()
                    
                    if not users:
                        break
                    
                    batch = []
                    for user in users:
                        user_data = {
                            'id': user['user_id'],
                            'email': user.get('email'),
                            'email_verified': user.get('email_verified', False),
                            'created_at': user.get('created_at'),
                            'password_hash': None,  # Auth0 doesn't export password hashes
                            'identities': user.get('identities', []),
                            'app_metadata': user.get('app_metadata', {}),
                            'user_metadata': user.get('user_metadata', {})
                        }
                        batch.append(user_data)
                    
                    yield batch
                    page += 1
    
    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Auth0 doesn't export password hashes for security"""
        return None


class DjangoImporter(BaseImporter):
    """Import users from Django authentication system"""
    
    async def connect(self) -> None:
        """Connect to Django database"""
        from sqlalchemy import create_engine, MetaData, Table
        from sqlalchemy.ext.asyncio import create_async_engine
        
        db_url = self.config.get('database_url')
        if not db_url:
            raise ValueError("Django database URL required")
        
        # Convert Django DB URL to async if needed
        if 'postgresql://' in db_url:
            db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://')
        elif 'mysql://' in db_url:
            db_url = db_url.replace('mysql://', 'mysql+aiomysql://')
        
        self.engine = create_async_engine(db_url)
        self.metadata = MetaData()
        
        # Load Django user table
        async with self.engine.begin() as conn:
            self.user_table = Table('auth_user', self.metadata, autoload_with=conn)
        
        print("✅ Connected to Django database")
    
    async def fetch_users(self, batch_size: int = 100) -> Generator[List[Dict], None, None]:
        """Fetch users from Django"""
        from sqlalchemy import select
        
        offset = 0
        
        async with self.engine.begin() as conn:
            while True:
                stmt = select(self.user_table).limit(batch_size).offset(offset)
                result = await conn.execute(stmt)
                users = result.fetchall()
                
                if not users:
                    break
                
                batch = []
                for user in users:
                    user_data = {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'is_active': user.is_active,
                        'is_staff': user.is_staff,
                        'is_superuser': user.is_superuser,
                        'created_at': user.date_joined,
                        'last_login': user.last_login,
                        'password_hash': user.password,
                        'password_algorithm': 'django_pbkdf2'  # Django default
                    }
                    batch.append(user_data)
                
                yield batch
                offset += batch_size
    
    def translate_password_hash(self, hash_str: str, algorithm: str) -> Optional[str]:
        """Translate Django password hash to Authy format"""
        # Django format: algorithm$iterations$salt$hash
        # Example: pbkdf2_sha256$260000$salt$hash
        parts = hash_str.split('$')
        
        if len(parts) == 4:
            algo, iterations, salt, hash_val = parts
            
            # Map Django algorithms to Authy
            algo_map = {
                'pbkdf2_sha256': 'pbkdf2_sha256',
                'pbkdf2_sha1': 'pbkdf2_sha1',
                'bcrypt': 'bcrypt',
                'argon2': 'argon2'
            }
            
            mapped_algo = algo_map.get(algo, None)
            if mapped_algo:
                # Return in Authy expected format
                return hash_str
        
        return None


def get_importer(provider: str, config: Dict[str, Any]) -> BaseImporter:
    """Factory function to get appropriate importer"""
    importers = {
        'firebase': FirebaseImporter,
        'auth0': Auth0Importer,
        'django': DjangoImporter,
        # Add more: cognito, supabase, etc.
    }
    
    if provider not in importers:
        raise ValueError(f"Unsupported provider: {provider}. Supported: {list(importers.keys())}")
    
    return importers[provider](config)
