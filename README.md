# 🔐 Advanced Keylogger & Password Recovery Tool

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## 🌟 Overview

This tool is a sophisticated dual-purpose security utility that combines keylogging capabilities with browser credential extraction. It can monitor keyboard activity and capture screenshots while also recovering saved passwords from popular web browsers including Chrome and Arc. Perfect for data recovery, parental monitoring, or security assessments on systems you own.

## ✨ Features

### 🎯 Keylogging Features

- ⌨️ **Keystroke Monitoring** - Records all keystrokes with timestamps
- 🖥️ **Active Window Tracking** - Logs which application is in use during typing
- 📸 **Automatic Screenshots** - Takes periodic screenshots of user activity
- 💾 **System Information Collection** - Gathers hardware and network details
- 🕒 **Configurable Intervals** - Customize screenshot frequency and monitoring behavior

### 🔑 Password Recovery Features

- 🧠 **Smart Recovery** - Intelligently extracts credentials even when encrypted
- 🌐 **Multi-Browser Support** - Works with Chrome, Arc, and more browsers
- 💻 **Cross-Platform** - Runs on Windows, macOS and Linux
- 🛡️ **Advanced Decryption** - Handles modern encryption methods including AES-GCM
- 📊 **JSON Export** - Saves results in clean, structured JSON format

## 🚀 Usage

1. Ensure you have Python 3.6+ installed
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the tool:

```bash
python keylogger.py
```

4. View keylogger results in the `logger.txt` file and browser data in the generated `browser_data.json` file

## 📋 Supported Browsers

| Browser | Windows | macOS | Linux |
| ------- | ------- | ----- | ----- |
| Chrome  | ✅      | ✅    | ✅    |
| Arc     | ✅      | ✅    | ✅    |

## 🛠️ How It Works

### Keylogging Module

The tool captures keyboard input using the `pynput` library, tracking:

- Key presses with timestamps
- Active application windows
- Periodic screenshots to document visual activity
- System and network information

### Password Recovery Module

The tool utilizes platform-specific methods to access and decrypt browser password databases:

- **Windows**: Uses DPAPI and AES-GCM decryption for modern browsers
- **macOS**: Accesses keychain data and employs PBKDF2 key derivation
- **Linux**: Implements Secret Service API and fallback mechanisms

## 📝 Output Examples

### Browser Data Output (browser_data.json)

```json
{
  "arc": {
    "passwords": [
      {
        "url": "https://example.com",
        "username": "user@example.com",
        "password": "yourpassword"
      }
    ],
    "history": { "data": [] },
    "count": 1
  }
}
```

### Keylogger Output (logger.txt)

```
Firefox - (H)
Firefox - (e)
Firefox - (l)
Firefox - (l)
Firefox - (o)
Firefox - ( )
Firefox - (w)
Firefox - (o)
Firefox - (r)
Firefox - (l)
Firefox - (d)
```

## ⚠️ Legal Disclaimer

This tool is provided for educational and legitimate purposes only. Use only on systems you own or have explicit permission to monitor. Unauthorized monitoring of third-party systems is illegal and unethical. Always inform users when monitoring is active in a workplace environment.

## 🔧 Requirements

- Python 3.6+
- pynput
- pillow (PIL)
- pycryptodomex
- cryptography
- pywin32 (Windows only)
- secretstorage (Linux only)

## 🤝 Contributing

Contributions are welcome! Feel free to submit pull requests to add support for more browsers or enhance existing functionality.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

⭐ Star this repository if you find it useful!
