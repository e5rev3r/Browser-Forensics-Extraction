"""Firefox Password Decryption Module.

Uses Mozilla's NSS (Network Security Services) library to decrypt
saved passwords from Firefox profiles.

This module handles:
- logins.json (encrypted credentials)
- key4.db (master key database, SQLite + NSS format)
- Both master password protected and unprotected profiles

Requirements:
- libnss3 system library (usually pre-installed on Linux)
- No pip packages needed
"""

import ctypes
from ctypes import (
    c_void_p, c_char_p, c_uint, c_int, c_size_t, c_ubyte,
    POINTER, Structure, byref, cast, create_string_buffer
)
import json
import base64
import sqlite3
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple
import tempfile
import shutil


# NSS Library structures and constants
class SECItem(Structure):
    """NSS SECItem structure for binary data."""
    _fields_ = [
        ('type', c_uint),
        ('data', POINTER(c_ubyte)),
        ('len', c_uint),
    ]


class NSSError(Exception):
    """NSS operation failed."""
    pass


class MasterPasswordRequired(Exception):
    """Master password is required but not provided."""
    pass


class ProfileNotFound(Exception):
    """Firefox profile not found."""
    pass


@dataclass
class DecryptedLogin:
    """Represents a decrypted login entry."""
    url: str
    username: str
    password: str
    hostname: str
    form_submit_url: Optional[str] = None
    http_realm: Optional[str] = None
    time_created: Optional[int] = None
    time_last_used: Optional[int] = None
    time_password_changed: Optional[int] = None
    times_used: Optional[int] = None


class NSSDecryptor:
    """Handles Firefox password decryption using NSS library."""
    
    # NSS library paths to try
    NSS_LIBRARY_PATHS = [
        '/usr/lib/libnss3.so',
        '/usr/lib64/libnss3.so',
        '/usr/lib/x86_64-linux-gnu/libnss3.so',
        '/usr/lib/i386-linux-gnu/libnss3.so',
        'libnss3.so',
    ]
    
    def __init__(self):
        self._nss = None
        self._initialized = False
        self._profile_path: Optional[Path] = None
        self._temp_dir: Optional[Path] = None
        
    def _load_nss_library(self) -> ctypes.CDLL:
        """Load the NSS library."""
        for path in self.NSS_LIBRARY_PATHS:
            try:
                nss = ctypes.CDLL(path)
                return nss
            except OSError:
                continue
        
        raise NSSError(
            "Could not load NSS library (libnss3.so). "
            "Install it with: sudo pacman -S nss (Arch) or "
            "sudo apt install libnss3 (Debian/Ubuntu)"
        )
    
    def _setup_nss_functions(self):
        """Setup NSS function signatures."""
        # NSS_Init
        self._nss.NSS_Init.argtypes = [c_char_p]
        self._nss.NSS_Init.restype = c_int
        
        # NSS_Shutdown
        self._nss.NSS_Shutdown.argtypes = []
        self._nss.NSS_Shutdown.restype = c_int
        
        # PK11_GetInternalKeySlot
        self._nss.PK11_GetInternalKeySlot.argtypes = []
        self._nss.PK11_GetInternalKeySlot.restype = c_void_p
        
        # PK11_FreeSlot
        self._nss.PK11_FreeSlot.argtypes = [c_void_p]
        self._nss.PK11_FreeSlot.restype = None
        
        # PK11_CheckUserPassword
        self._nss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
        self._nss.PK11_CheckUserPassword.restype = c_int
        
        # PK11_Authenticate
        self._nss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]
        self._nss.PK11_Authenticate.restype = c_int
        
        # PK11SDR_Decrypt
        self._nss.PK11SDR_Decrypt.argtypes = [POINTER(SECItem), POINTER(SECItem), c_void_p]
        self._nss.PK11SDR_Decrypt.restype = c_int
        
        # SECITEM_FreeItem
        self._nss.SECITEM_FreeItem.argtypes = [POINTER(SECItem), c_int]
        self._nss.SECITEM_FreeItem.restype = None
        
        # PK11_NeedLogin
        self._nss.PK11_NeedLogin.argtypes = [c_void_p]
        self._nss.PK11_NeedLogin.restype = c_int
    
    def _create_temp_profile(self, profile_path: Path) -> Path:
        """Create a temporary copy of the profile for NSS.
        
        NSS modifies the database files, so we work on a copy.
        """
        self._temp_dir = Path(tempfile.mkdtemp(prefix='firefox_decrypt_'))
        
        # Copy only the necessary files
        files_to_copy = ['key4.db', 'key3.db', 'cert9.db', 'cert8.db', 'logins.json']
        
        for filename in files_to_copy:
            src = profile_path / filename
            if src.exists():
                shutil.copy2(src, self._temp_dir / filename)
        
        return self._temp_dir
    
    def _cleanup_temp(self):
        """Clean up temporary directory."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
    
    def initialize(self, profile_path: Path, master_password: str = "") -> bool:
        """Initialize NSS with the Firefox profile.
        
        Args:
            profile_path: Path to Firefox profile directory
            master_password: Master password if set (empty string if none)
        
        Returns:
            True if initialization successful
        
        Raises:
            ProfileNotFound: If profile doesn't exist
            MasterPasswordRequired: If master password needed but not provided
            NSSError: If NSS initialization fails
        """
        profile_path = Path(profile_path)
        
        if not profile_path.exists():
            raise ProfileNotFound(f"Profile not found: {profile_path}")
        
        # Check for key database
        key4_path = profile_path / 'key4.db'
        key3_path = profile_path / 'key3.db'
        
        if not key4_path.exists() and not key3_path.exists():
            raise ProfileNotFound(
                f"No key database found in profile. "
                f"Expected key4.db or key3.db at {profile_path}"
            )
        
        # Load NSS library
        self._nss = self._load_nss_library()
        self._setup_nss_functions()
        
        # Create temporary profile copy
        temp_profile = self._create_temp_profile(profile_path)
        self._profile_path = profile_path
        
        # Initialize NSS with the profile
        # Use sql: prefix for key4.db (SQLite format)
        config_dir = f"sql:{temp_profile}".encode('utf-8')
        
        result = self._nss.NSS_Init(config_dir)
        if result != 0:
            # Try without sql: prefix for older key3.db
            config_dir = str(temp_profile).encode('utf-8')
            result = self._nss.NSS_Init(config_dir)
            if result != 0:
                self._cleanup_temp()
                raise NSSError(f"NSS_Init failed with error code {result}")
        
        self._initialized = True
        
        # Get the internal key slot
        slot = self._nss.PK11_GetInternalKeySlot()
        if not slot:
            self.shutdown()
            raise NSSError("Failed to get internal key slot")
        
        try:
            # Check if master password is needed
            needs_login = self._nss.PK11_NeedLogin(slot)
            
            if needs_login:
                # Try to authenticate with provided password
                password = master_password.encode('utf-8') if master_password else b""
                auth_result = self._nss.PK11_CheckUserPassword(slot, password)
                
                if auth_result != 0:
                    if not master_password:
                        self.shutdown()
                        raise MasterPasswordRequired(
                            "This profile has a master password set. "
                            "Please provide the master password."
                        )
                    else:
                        self.shutdown()
                        raise NSSError("Invalid master password")
        finally:
            self._nss.PK11_FreeSlot(slot)
        
        return True
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt a piece of encrypted data.
        
        Args:
            encrypted_data: Base64-decoded encrypted data
        
        Returns:
            Decrypted string
        """
        if not self._initialized:
            raise NSSError("NSS not initialized. Call initialize() first.")
        
        # Create input SECItem
        input_item = SECItem()
        input_item.type = 0  # siBuffer
        input_item.data = cast(
            ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
            POINTER(c_ubyte)
        )
        input_item.len = len(encrypted_data)
        
        # Create output SECItem
        output_item = SECItem()
        output_item.type = 0
        output_item.data = None
        output_item.len = 0
        
        # Decrypt
        result = self._nss.PK11SDR_Decrypt(byref(input_item), byref(output_item), None)
        
        if result != 0:
            raise NSSError(f"Decryption failed with error code {result}")
        
        try:
            # Extract decrypted data
            decrypted = bytes(output_item.data[:output_item.len])
            return decrypted.decode('utf-8')
        finally:
            # Free the output item
            if output_item.data:
                self._nss.SECITEM_FreeItem(byref(output_item), 0)
    
    def decrypt_logins(self) -> List[DecryptedLogin]:
        """Decrypt all logins from the profile.
        
        Returns:
            List of decrypted login entries
        """
        if not self._initialized or not self._profile_path:
            raise NSSError("NSS not initialized. Call initialize() first.")
        
        logins_path = self._profile_path / 'logins.json'
        
        if not logins_path.exists():
            return []
        
        with open(logins_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        logins = data.get('logins', [])
        decrypted_logins = []
        
        for login in logins:
            try:
                # Decrypt username and password
                encrypted_username = base64.b64decode(login.get('encryptedUsername', ''))
                encrypted_password = base64.b64decode(login.get('encryptedPassword', ''))
                
                username = self.decrypt(encrypted_username) if encrypted_username else ''
                password = self.decrypt(encrypted_password) if encrypted_password else ''
                
                decrypted_logins.append(DecryptedLogin(
                    url=login.get('hostname', ''),
                    username=username,
                    password=password,
                    hostname=login.get('hostname', ''),
                    form_submit_url=login.get('formSubmitURL'),
                    http_realm=login.get('httpRealm'),
                    time_created=login.get('timeCreated'),
                    time_last_used=login.get('timeLastUsed'),
                    time_password_changed=login.get('timePasswordChanged'),
                    times_used=login.get('timesUsed'),
                ))
            except Exception as e:
                # Skip entries that fail to decrypt
                print(f"Warning: Failed to decrypt entry for {login.get('hostname', 'unknown')}: {e}",
                      file=sys.stderr)
                continue
        
        return decrypted_logins
    
    def shutdown(self):
        """Shutdown NSS and cleanup."""
        if self._initialized and self._nss:
            self._nss.NSS_Shutdown()
            self._initialized = False
        self._cleanup_temp()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
        return False


def decrypt_firefox_passwords(
    profile_path: Path,
    master_password: str = ""
) -> Tuple[List[DecryptedLogin], Optional[str]]:
    """High-level function to decrypt Firefox passwords.
    
    Args:
        profile_path: Path to Firefox profile
        master_password: Master password if set
    
    Returns:
        Tuple of (list of decrypted logins, error message or None)
    """
    try:
        with NSSDecryptor() as decryptor:
            decryptor.initialize(profile_path, master_password)
            logins = decryptor.decrypt_logins()
            return logins, None
    except MasterPasswordRequired as e:
        return [], str(e)
    except ProfileNotFound as e:
        return [], str(e)
    except NSSError as e:
        return [], str(e)
    except Exception as e:
        return [], f"Unexpected error: {str(e)}"


def check_master_password_required(profile_path: Path) -> bool:
    """Check if a profile requires a master password.
    
    Args:
        profile_path: Path to Firefox profile
    
    Returns:
        True if master password is required
    """
    key4_path = profile_path / 'key4.db'
    
    if not key4_path.exists():
        return False
    
    try:
        conn = sqlite3.connect(f"file:{key4_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        # Check the metaData table for password-check entry
        cursor.execute(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'"
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            # If there's encrypted data, a master password might be set
            # The actual check requires NSS, but this is a quick heuristic
            return True
        
        return False
    except Exception:
        return False


# CLI interface for standalone testing
if __name__ == '__main__':
    import argparse
    import getpass
    
    parser = argparse.ArgumentParser(description='Decrypt Firefox saved passwords')
    parser.add_argument('profile', help='Path to Firefox profile directory')
    parser.add_argument('-p', '--password', help='Master password (will prompt if needed)')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    profile = Path(args.profile)
    
    if not profile.exists():
        print(f"Error: Profile not found: {profile}", file=sys.stderr)
        sys.exit(1)
    
    # Check if master password needed
    master_password = args.password or ""
    
    # Try to decrypt
    logins, error = decrypt_firefox_passwords(profile, master_password)
    
    if error:
        if "master password" in error.lower():
            # Prompt for password
            master_password = getpass.getpass("Master password: ")
            logins, error = decrypt_firefox_passwords(profile, master_password)
    
    if error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    
    if not logins:
        print("No saved passwords found.")
        sys.exit(0)
    
    if args.json:
        output = [
            {
                'url': l.url,
                'username': l.username,
                'password': l.password,
                'times_used': l.times_used,
            }
            for l in logins
        ]
        print(json.dumps(output, indent=2))
    else:
        print(f"\nFound {len(logins)} saved password(s):\n")
        for i, login in enumerate(logins, 1):
            print(f"[{i}] {login.hostname}")
            print(f"    Username: {login.username}")
            print(f"    Password: {login.password}")
            if login.times_used:
                print(f"    Used: {login.times_used} times")
            print()
