# Steganography Brute Force Tool

A comprehensive cybersecurity defense tool designed to detect and extract hidden messages from image files using various steganographic techniques.

> **Academic Project**: This project was developed as part of **Task 3 Week 3** for the **IDN Cybersecurity Bootcamp** program.

## 🎓 Academic Context

This tool was developed as part of the **IDN Cybersecurity Bootcamp** curriculum:
- **Program**: IDN Cybersecurity Bootcamp
- **Assignment**: Task 3 Week 3 - Brute Force Tools Development
- **Focus**: Defensive cybersecurity tools and steganography analysis
- **Educational Goal**: Understanding steganographic threats and detection methods

### Assignment Requirements Met
- ✅ Brute force functionality (steganography password cracking)
- ✅ Non-IP based brute force approach
- ✅ Practical cybersecurity application
- ✅ Educational and defensive purpose

## 🔍 Overview

This tool helps cybersecurity professionals and enthusiasts identify potential steganographic content in image files. With the increasing use of steganography in malware distribution and covert communications, this tool serves as an essential defensive mechanism.

## ✨ Features

- **Multi-Method Detection**: Supports multiple steganography detection techniques
- **Steghide Brute Force**: Attempts extraction using common passwords
- **LSB Analysis**: Detects Least Significant Bit steganography patterns
- **Metadata Inspection**: Analyzes suspicious metadata within image files
- **Statistical Analysis**: Identifies anomalous bit patterns
- **Comprehensive Reporting**: Generates detailed analysis reports

## 🛠️ Installation

### Prerequisites

- Python 3.6+
- pip package manager

### Required Dependencies

```bash
pip install Pillow numpy
```

### External Tools

**For Linux/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install steghide
```

**For macOS:**
```bash
brew install steghide
```

**For Windows:**
Download steghide from the official website and add to PATH.

## 🚀 Usage

### Basic Usage

```bash
python stego_bruteforce.py image.jpg
```

### Verbose Mode

```bash
python stego_bruteforce.py -v suspicious_image.png
```

### Command Line Options

- `file`: Target image file to analyze (required)
- `-v, --verbose`: Enable verbose output for detailed analysis
- `-h, --help`: Show help message

## 📊 Detection Methods

### 1. Steghide Brute Force
- Tests common passwords against steghide-embedded content
- Password dictionary includes: empty password, "password", "123456", "admin", etc.
- Automatically extracts and displays hidden content when found

### 2. LSB (Least Significant Bit) Analysis
- Examines pixel data for hidden messages in LSB channels
- Performs statistical analysis of bit distribution
- Attempts to decode binary data into readable text

### 3. Metadata Inspection
- Analyzes EXIF data for suspicious entries
- Detects anomalous file sizes compared to image dimensions
- Identifies potentially malicious metadata patterns

## 📈 Output Example

```
╔══════════════════════════════════════════════════════════════╗
║                  STEGANOGRAPHY BRUTE FORCER                  ║
║                   Cybersecurity Defense Tool                 ║
║              Detect Hidden Messages in Images                ║
╚══════════════════════════════════════════════════════════════╝

[+] Analyzing file: suspicious_image.jpg
[i] File size: 245760 bytes
[i] File hash (MD5): a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

[*] Testing method: STEGHIDE
[!] FOUND with steghide! Password: 'secret'
[!] Extracted 156 bytes
[!] Content preview: This is a hidden message...

[*] Testing method: LSB
[!] Possible LSB steganography detected!
[!] Sample text: Secret data hidden in image...

============================================================
STEGANOGRAPHY ANALYSIS REPORT
============================================================

[1] File: suspicious_image.jpg
    Method: steghide
    Details: {'password': 'secret', 'size': 156, 'content_preview': b'This is a hidden message...'}

[!] Total suspicious files: 1
[!] Manual verification recommended for all detections.
```

## 🎯 Use Cases

### Cybersecurity Defense
- **Malware Detection**: Identify malware hidden in image files
- **Incident Response**: Analyze suspicious images from security incidents
- **Forensic Analysis**: Extract hidden evidence from digital images

### Educational Purposes
- **Learning Steganography**: Understand how steganographic techniques work
- **Security Training**: Practice steganography detection skills
- **Research**: Academic research on steganographic methods

## ⚠️ Important Notes

### Ethical Usage
This tool is designed for:
- ✅ Analyzing your own files
- ✅ Authorized security assessments
- ✅ Educational and research purposes
- ✅ Defensive cybersecurity operations

### Legal Considerations
- Only use on files you own or have explicit permission to analyze
- Comply with local laws and regulations
- Respect privacy and confidentiality

## 🔧 Advanced Configuration

### Custom Password Dictionary

You can modify the `common_passwords` list in the code to add your own password dictionary:

```python
self.common_passwords = [
    "", "password", "123456", "admin", "secret",
    # Add your custom passwords here
    "custom_pass", "organization_name"
]
```

### Supported File Formats

Currently supports:
- JPEG (.jpg, .jpeg)
- PNG (.png)
- BMP (.bmp)
- Other PIL-supported formats

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes
- New detection methods
- Performance improvements
- Documentation enhancements

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **IDN Cybersecurity Bootcamp** for providing the learning opportunity and assignment framework
- Thanks to the steganography research community
- PIL/Pillow developers for excellent image processing capabilities
- Open source steganography tools that inspired this project
- Bootcamp instructors and fellow students for guidance and collaboration

## 📞 Support

If you encounter issues or have questions:

1. Check the [Issues](../../issues) section
2. Create a new issue with detailed information
3. Include sample files (if not sensitive) for better support

## 🛡️ Disclaimer

This tool is provided for educational and legitimate security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers assume no responsibility for misuse of this tool.

---

**Made with ❤️ for the cybersecurity community**
