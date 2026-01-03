# 🔍 Browser Forensics Extraction Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com)

Forensic tool for extracting and analyzing browser artifacts from Firefox, Chrome, Edge, Brave, Opera, and Vivaldi. Features automatic dependency management, multi-browser support, and comprehensive password decryption.

## 🚀 Quick Start

```bash
# Just run it! Dependencies auto-install on first run
python main.py
```

That's it! The tool automatically checks and installs required dependencies.

## ✨ Features

### Core Capabilities
- 🌐 **Multi-Browser Support** - Firefox, Chrome, Edge, Brave, Opera, Vivaldi
- 🖥️ **Cross-Platform** - Windows, Linux (macOS partial support)
- 🔎 **Comprehensive Extraction** - History, cookies, passwords, forms, bookmarks, downloads
- 📊 **Multiple Output Formats** - JSON artifacts, HTML reports, terminal output

### Password Decryption
- 🔓 **Firefox NSS** - Native NSS library integration with master password support
- 🔐 **Chromium Multi-Key** - Enhanced decryption with multiple fallback strategies
- ✅ **Desktop Support** - GNOME, KDE, XFCE, and headless environments
- 🎯 **v10/v11 Decryption** - Full support for standard Chromium encryption
- ⚠️ **v20 Detection** - Clear indicators for App-Bound encrypted data

### Cookie Decryption
- 🍪 **Full Cookie Support** - Decrypt v10, v11 encrypted cookies
- � **Clear Status** - Success and failure indicators

### User Experience
- 🎨 **Color-Coded Output** - Clear visual feedback for results
- 💬 **Interactive Mode** - User-friendly prompts and browser/profile selection
- 🔍 **Auto-Detection** - Automatically finds all installed browsers and profiles
- 🚀 **Auto-Setup** - Dependencies install automatically on first run

## 📖 Usage

### Basic Usage

```bash
# Auto-detect all browsers (interactive)
python main.py

# List all detected browsers
python main.py --list-browsers

# Extract from specific browser
python main.py -b firefox
python main.py -b chrome
python main.py -b brave
```

### Selective Extraction

```bash
# Extract only history
python main.py -e history

# Extract multiple categories
python main.py -e history cookies bookmarks

# Print to terminal only (no files)
python main.py -e history --print-only

# Extract passwords only
python main.py -e passwords

# Skip password decryption
python main.py --no-passwords
```

### Advanced Options

```bash
# Non-interactive extraction
python main.py -b firefox -e all -n -o ./output

# Custom output directory
python main.py --output ~/forensics_output

# Check environment compatibility
python main.py --check-env
```

## 🔧 CLI Reference

| Flag | Description |
|------|-------------|
| `-b, --browser` | Browser: `firefox`, `chrome`, `chromium`, `edge`, `brave`, `opera`, `vivaldi`, `auto` |
| `-e, --extract` | Categories: `history`, `cookies`, `passwords`, `downloads`, `bookmarks`, `autofill`, `extensions`, `all` |
| `--list-browsers` | List detected browsers and profiles |
| `--print-only` | Print to terminal only (no files) |
| `--no-passwords` | Skip password decryption |
| `-o, --output` | Output directory path |
| `-n, --no-interactive` | Disable interactive prompts |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet output |
| `--check-env` | Check environment compatibility |

## 📁 Project Structure

```
Browser-Key-Extraction/
├── main.py              # Main entry point with auto-setup
├── browser_profiles.py  # Browser detection & profile management
├── extractors.py        # Database extraction classes (Firefox/Chromium)
├── sql_queries.py       # Optimized SQL queries for browser databases
├── nss_decrypt.py       # Firefox NSS password decryption
├── chromium_decrypt.py  # Chromium multi-key password/cookie decryption
├── html_report.py       # Interactive HTML report generation
├── requirements.txt     # Python dependencies
├── README.md            # Complete documentation
├── LICENSE              # MIT License
└── .gitignore           # Git ignore patterns
```

## 🔧 Installation

### Option 1: Automatic (Recommended)
```bash
# Clone the repository
git clone https://github.com/yourusername/Browser-Key-Extraction.git
cd Browser-Key-Extraction

# Just run it - dependencies auto-install!
python main.py
```

### Option 2: Manual Setup
```bash
# Clone repository
git clone https://github.com/yourusername/Browser-Key-Extraction.git
cd Browser-Key-Extraction

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

### System Dependencies

**Linux (Debian/Ubuntu):**
```bash
# For Firefox password decryption
sudo apt install libnss3

# For GNOME Keyring support (Chromium browsers)
sudo apt install libsecret-1-0
```

**Linux (Arch):**
```bash
sudo pacman -S nss libsecret
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install nss libsecret
```

**Windows:**
- Firefox must be installed (bundled NSS DLLs)
- For v20 decryption: Run as Administrator

## 📤 Output Format

The tool generates output in the following structure:
```
output_folder/
├── report.html          # Interactive HTML report
├── summary.txt          # Quick text summary
└── artifacts/           # JSON data files
    ├── history.json
    ├── cookie.json
    ├── password.json
    ├── autofill.json
    ├── bookmark.json
    └── download.json
```

## 🔒 Password Decryption

### Chromium Multi-Key Decryption

The tool implements multiple fallback strategies for maximum compatibility with different encryption configurations and desktop environments.

**Desktop Environment Support:**
- ✅ GNOME (including Kali Linux)
- ✅ KDE Plasma (KWallet)
- ✅ XFCE/Cinnamon/MATE
- ✅ Headless/unknown (fallback mode)

### Firefox NSS Decryption
- **Linux**: Uses system `libnss3` library (install: `sudo apt install libnss3`)
- **Windows**: Uses Firefox bundled NSS DLLs (Firefox must be installed)
- **Master Password**: Interactive prompt if protected

### Chromium v10/v11 Decryption (Standard)
- **v10** (AES-256-GCM): Windows DPAPI or Linux keyring-derived key
- **v11** (AES-128-CBC): Linux-only, keyring or peanuts password
- **Automatic**: Tool detects version and applies correct decryption

### Chromium v20 App-Bound Encryption (Limited Support)

Starting Chrome 127+ (July 2024), **App-Bound Encryption** is enabled by default.

**Status Indicators:**
- `[O]` - Successfully decrypted (green)
- `[X]` - Decryption failed (red)

**v20 Limitations:**
- Requires browser code-signing certificate
- External tools cannot decrypt
- Tool shows: `[v20 PROTECTED - Run as Admin]`

**Workaround for v20:**
1. Run as Administrator (Windows)
2. Install `PythonForWindows`: `pip install PythonForWindows`
3. Or export passwords from browser (Settings → Passwords → Export)

## 📊 Extracted Data

| Category | Firefox | Chromium | Notes |
|----------|---------|----------|-------|
| Browsing History | ✅ | ✅ | URL, title, visit time, visit count |
| Cookies | ✅ | ✅ | Decrypted values with expiration |
| Bookmarks | ✅ | ✅ | Hierarchical structure |
| Downloads | ✅ | ✅ | File path, URL, download time |
| Saved Passwords | ✅ | ✅ | Multi-key decryption, v10/v11 support |
| Form Autofill | ✅ | ✅ | Field names and values |
| Extensions | ✅ | ✅ | Name, version, permissions |
| Site Permissions | ✅ | - | Firefox-specific |

### Data Quality & Integrity

- **Color-coded output**: Visual feedback for success/failure
- **Error handling**: Graceful fallback for locked databases, corrupted data
- **SHA256 hashes**: Evidence integrity verification in summary.txt
- **Timestamp precision**: Microsecond accuracy preserved

## 🚀 Production Features

### Reliability
- ✅ Automatic dependency installation and virtual environment setup
- ✅ Graceful error handling with detailed error messages
- ✅ Database locking detection with retry mechanism
- ✅ Memory-efficient streaming for large datasets
- ✅ Safe read-only database access

### Security
- ✅ No network connections (100% local operation)
- ✅ No data transmission or telemetry
- ✅ Read-only file access (no modifications to browser data)
- ✅ Secure credential handling in memory
- ✅ Clear warnings for privileged operations

### Platform Compatibility
- ✅ Windows 10/11 (tested)
- ✅ Linux: Kali, Ubuntu, Debian, Arch, Fedora (tested)
- ✅ Python 3.9+ required
- ⚠️ macOS: Partial support (Firefox works, Chromium limited)

## 📈 Performance

- **Fast extraction**: 1000+ history entries/second
- **Low memory**: < 100MB for typical browser profiles
- **Concurrent safe**: Uses database snapshots, doesn't lock browser
- **Large dataset handling**: Streaming queries for multi-GB databases

## ⚠️ Legal & Ethical Use

### Intended Use Cases
✅ **Authorized forensic investigations** with proper legal authority  
✅ **Security audits** of systems you own or have written permission to analyze  
✅ **Personal data recovery** from your own browser profiles  
✅ **Educational research** in controlled environments  
✅ **IT support** with user consent  

### Prohibited Uses
❌ Unauthorized access to other users' data  
❌ Corporate espionage or competitive intelligence  
❌ Privacy violations without consent  
❌ Any illegal surveillance or data theft  

### Your Responsibility
By using this tool, you agree to:
- Obtain proper authorization before accessing any system or data
- Comply with all applicable laws and regulations (GDPR, CCPA, CFAA, etc.)
- Use the tool ethically and responsibly
- Not use this tool for malicious purposes

**The authors are not responsible for misuse of this tool.**

## 🐛 Troubleshooting

### Common Issues

**"No browsers detected"**
- Ensure browsers are installed in standard locations
- Try specifying profile path manually: `python main.py /path/to/profile`

**"libnss3 not found" (Linux/Firefox)**
```bash
# Debian/Ubuntu
sudo apt install libnss3

# Arch
sudo pacman -S nss

# Fedora
sudo dnf install nss
```

**"Database is locked"**
- Close the browser completely
- Tool uses temporary copies to avoid locking issues
- Check for browser background processes

**"All decryption failed" (Chromium)**
- Close the browser completely
- Tool uses temporary copies to avoid locking issues
- Check for browser background processes
- Data may be corrupted or encrypted with unavailable key

**v20 passwords showing [v20 PROTECTED]**
- Run as Administrator (Windows)
- Install PythonForWindows: `pip install PythonForWindows`
- Or export from browser: Settings → Passwords → Export

### Debug Mode

```bash
# Show detailed output
python main.py -v

# Check environment compatibility
python main.py --check-env

# Test specific browser
python main.py -b brave
```

## 🤝 Contributing

Contributions welcome! Areas of interest:
- macOS Keychain support for Chromium browsers
- Additional browser support (Safari, Edge Legacy)
- Performance optimizations
- Test coverage improvements

## � License

MIT License - see [LICENSE](LICENSE) for details.

---

**⚡ Quick Start:** `python main.py`  
**🐛 Issues:** Report bugs and request features via GitHub Issues  
**⭐ Star this repo** if you find it useful!
