# 🔐 Advanced Browser Password Recovery Tool

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## 🌟 Overview

This tool is a sophisticated browser credential extraction utility designed to recover saved passwords from popular web browsers including Chrome and Arc. Perfect for data recovery when you've forgotten your passwords or need to conduct security assessments.

## ✨ Features

- 🧠 **Smart Recovery** - Intelligently extracts credentials even when encrypted
- 🌐 **Multi-Browser Support** - Works with Chrome, Arc, and more browsers
- 💻 **Cross-Platform** - Runs on Windows, macOS and Linux
- 🛡️ **Advanced Decryption** - Handles modern encryption methods including AES-GCM
- 📊 **JSON Export** - Saves results in clean, structured JSON format
- 🧩 **Extensible** - Easy to add support for more browsers

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

4. View results in the terminal and in the generated `browser_data.json` file

## 📋 Supported Browsers

| Browser | Windows | macOS | Linux |
| ------- | ------- | ----- | ----- |
| Chrome  | ✅      | ✅    | ✅    |
| Arc     | ✅      | ✅    | ✅    |

## 🛠️ How It Works

The tool utilizes platform-specific methods to access and decrypt browser password databases:

- **Windows**: Uses DPAPI and AES-GCM decryption for modern browsers
- **macOS**: Accesses keychain data and employs PBKDF2 key derivation
- **Linux**: Implements Secret Service API and fallback mechanisms

## 📝 Output Example

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

## ⚠️ Legal Disclaimer

This tool is provided for educational and legitimate recovery purposes only. Use only on systems you own or have permission to test. Unauthorized use against third-party systems is illegal and unethical.

## 🔧 Requirements

- Python 3.6+
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
