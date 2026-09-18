# 🛡️ Cybersecurity Awareness Platform Kit

A beginner-friendly cybersecurity awareness and security-analysis platform designed to help users understand common cyber threats, practice identifying phishing attacks, evaluate password strength, analyze URLs and files, inspect APK security characteristics, and learn basic network-security concepts.

The project combines multiple cybersecurity learning utilities into one simple web platform built with **Python and Flask**.

---

## 🎯 Project Objective

The main objective of this project is to promote cybersecurity awareness and help users develop safer digital habits through practical, interactive security tools.

The platform provides educational demonstrations and security-analysis utilities covering:

- 🛡️ Cybersecurity awareness
- 🎣 Phishing awareness
- 🔐 Password security
- 🔑 Strong password generation
- 🔎 TCP port scanning
- 🌐 URL security analysis
- 📄 File safety analysis
- 📱 APK security analysis
- 🦠 VirusTotal threat intelligence integration

---

# 🚀 Features

## 1. 🛡️ Cyber Awareness

Provides educational information about common cybersecurity threats and safer digital practices.

### Topics Include

- Cybersecurity fundamentals
- Online safety
- Social engineering
- Phishing
- Password security
- Account protection
- Safe browsing practices
- Cyber hygiene

---

## 2. 🎣 Phishing Demo

An educational phishing demonstration designed to help users understand how phishing attacks work and how attackers may attempt to collect sensitive information.

It helps users recognize suspicious:

- Links
- Messages
- Emails
- Login pages
- Requests for sensitive information

> **Educational Purpose Only:** This feature is designed to demonstrate phishing concepts and improve security awareness. It should not be used to collect real credentials or target real users.

---

## 3. 🔐 Password Strength Checker

Allows users to evaluate the strength of a password using local security heuristics.

The password can be categorized into:

- Normal
- Medium
- Strong

The analyzer considers characteristics such as:

- Password length
- Uppercase characters
- Lowercase characters
- Numbers
- Special characters
- Common password patterns

### 🔒 Privacy

Passwords are analyzed locally by the application and are not intentionally stored as part of the analysis process.

The feature is designed for cybersecurity education and password-security awareness.

---

## 4. 🔑 Strong Password Generator

Generates strong random passwords using Python's secure random-generation facilities.

The generator demonstrates the importance of using:

- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Sufficient password length

### Default Generated Password Length

**18 characters**

The generated passwords are intended for demonstration and security-awareness purposes.

---

## 5. 🔎 Port Scanner

The Port Scanner performs a TCP connection scan against a specified hostname or IP address.

The scanner is designed to demonstrate basic network-security and port-scanning concepts.

### Features

- Scans TCP ports from 1 to 1024 by default
- Uses concurrent scanning for faster results
- Applies a connection timeout
- Resolves hostnames before scanning
- Detects accessible TCP ports
- Displays open ports in numerical order
- Handles invalid or unreachable targets gracefully
- Prevents indefinite waiting during individual connection attempts

### Example

Enter a target such as:

```text
127.0.0.1
```

The default scanner checks:

```text
1 → 1024
```

For example, if a local service is listening on a port within the configured range, the scanner can report that port as open.

### 🔒 Security Notice

Use the Port Scanner only against:

- Systems you own
- Your own lab environment
- Authorized testing environments
- Systems for which you have explicit permission

Do not scan systems or networks without authorization.

---

## 6. 🌐 URL & File Safety Analyzer

The URL & File Safety Analyzer is one of the main security-analysis features of the platform.

It provides two analysis modes:

```text
             URL & FILE SAFETY ANALYZER
                       │
              ┌────────┴────────┐
              ▼                 ▼
        🌍 URL Analysis    📄 File Analysis
```

---

### 🌍 URL Analysis

Users can submit a URL for security analysis.

The analyzer combines local URL heuristics with VirusTotal threat intelligence when available.

### Local URL Analysis

The application examines characteristics such as:

- HTTPS usage
- IP-address-based URLs
- Suspicious keywords
- URL length
- Encoded characters
- Suspicious URL patterns
- Excessive subdomains
- The `@` character in URLs
- Credential-related terms
- Brand-impersonation patterns
- Suspicious URL structure

These checks can identify characteristics commonly associated with suspicious URLs.

> **Important:** URL structure alone cannot prove that a website is malicious or safe.

---

### 🦠 VirusTotal Integration

The platform can integrate with the VirusTotal API to obtain additional threat-intelligence information.

The application can:

1. Receive the submitted URL
2. Perform local analysis
3. Submit the URL to VirusTotal
4. Retrieve the available analysis
5. Process the security-engine results
6. Present the information through the application's own security-report interface

### VirusTotal Information Can Include

- Malicious detections
- Suspicious detections
- Harmless results
- Undetected results
- Security-vendor detections
- Analysis status
- Phishing-related detections when reported by engines
- Redirect information when available
- Final URL information when available

### Example Workflow

```text
User enters URL
       │
       ▼
Flask receives URL
       │
       ▼
Local URL analysis
       │
       ▼
VirusTotal API request
       │
       ▼
Threat-intelligence response
       │
       ▼
Result processing
       │
       ▼
Security report
       │
       ▼
User sees analysis
```

---

### 🧠 URL Risk Classification

Depending on the available local analysis and VirusTotal results, the application can display classifications such as:

- `HIGH RISK`
- `MALICIOUS`
- `PHISHING DETECTED`
- `SUSPICIOUS`
- `NO MALICIOUS DETECTION`
- `NOT DETERMINED`

### Important Security Principle

An HTTPS connection does **not** automatically mean that a website is safe.

Similarly, a URL with no current malicious detections should not be interpreted as an absolute guarantee that the website is safe.

Threat intelligence changes over time, and automated security tools cannot guarantee detection of every malicious URL.

---

## 7. 📄 File Safety Analysis

The platform allows users to upload supported files for local static analysis.

### Analysis Workflow

```text
File Upload
     │
     ▼
Validate File Extension
     │
     ▼
Generate Temporary Filename
     │
     ▼
Save Temporarily
     │
     ▼
Analyze File
     │
     ▼
Generate Security Information
     │
     ▼
Delete Temporary File
```

The analyzer can collect information such as:

- Original filename
- File extension
- File size
- SHA-256 hash
- Security indicators
- Risk classification

Temporary uploaded files are removed after processing.

---

## 8. 🔐 SHA-256 File Hashing

The file analyzer can calculate a SHA-256 hash for an uploaded file.

A hash acts as a digital fingerprint of the file.

```text
File
  │
  ▼
SHA-256 Algorithm
  │
  ▼
Digital Fingerprint
```

If the contents of a file change, its SHA-256 hash will also change.

SHA-256 is commonly used in cybersecurity for:

- File identification
- Malware research
- Integrity verification
- Threat intelligence
- Incident investigation

---

## 9. 📱 APK Security Analyzer

The APK Security Analyzer performs local static inspection of Android APK packages without executing the APK.

### Local APK Analysis Includes

- APK archive validation
- File count
- DEX file detection
- Native library detection
- Suspicious filenames
- AndroidManifest.xml inspection
- Security-sensitive permissions
- Application components
- Embedded URLs
- Domain extraction
- Suspicious keywords
- SHA-256 calculation
- Local risk classification

### Security-Sensitive Permissions

The analyzer can identify permissions related to capabilities such as:

- SMS access
- Phone calls
- Contacts
- Camera
- Microphone
- Location
- Storage
- Package installation
- Overlay windows
- Accessibility services
- Boot completion
- Internet communication
- Foreground services

> **Important:** A permission by itself does not prove that an APK is malicious. Legitimate applications may require sensitive permissions depending on their functionality.

---

### 🦠 APK VirusTotal Analysis

When configured, the APK analyzer can use VirusTotal to obtain additional file-threat intelligence.

The workflow is:

```text
APK Upload
     │
     ▼
Local Static Analysis
     │
     ▼
SHA-256 Calculation
     │
     ▼
VirusTotal Hash Lookup
     │
     ├── Existing Report
     │       │
     │       ▼
     │   Analyze Report
     │
     └── No Report
             │
             ▼
       Upload APK
             │
             ▼
       VirusTotal Analysis
             │
             ▼
       Security Report
```

### VirusTotal Results Can Include

- Malicious detections
- Suspicious detections
- Harmless results
- Undetected results
- Security-engine detections
- File hashes
- File type
- File size
- Reputation
- Threat classifications
- Tags

The application presents the available information through its own security-analysis interface.

---

# 🛠️ Technologies Used

## Frontend

- HTML5
- CSS3
- JavaScript

## Backend

- Python
- Flask

## Security & Analysis

- Python `socket`
- SHA-256 hashing
- Static file analysis
- APK archive inspection
- URL heuristics
- TCP port scanning
- VirusTotal API integration

## Development & Deployment

- Git
- GitHub
- Visual Studio Code
- Render

---

# 📦 Python Dependencies

The project currently uses packages such as:

```text
Flask
gunicorn
requests
```

Python standard-library modules are also used for functionality such as:

- `socket`
- `hashlib`
- `os`
- `re`
- `time`
- `zipfile`
- `uuid`
- `concurrent.futures`

---

# 📂 Project Structure

```text
cybersecurity-toolkit/
│
├── app.py
├── password_security.py
├── port_scanner.py
├── url_analyzer.py
├── file_analyzer.py
├── apk_analyzer.py
├── requirements.txt
│
├── uploads/
│
├── static/
│   └── style.css
│
└── templates/
    ├── index.html
    ├── awareness.html
    ├── phishing_demo.html
    ├── password_security.html
    ├── password_generator.html
    ├── portscan.html
    ├── url_analyzer.html
    └── apk_analyzer.html
```

> The project structure may change as additional security features and improvements are developed.

---

# 🔄 How the Platform Works

```text
                         USER
                           │
                           ▼
              🛡️ Cybersecurity Platform
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   🛡️ Awareness       🎣 Phishing       🔐 Password
                                             │
                                      ┌──────┴──────┐
                                      ▼             ▼
                                  Strength       Generator
                                   Checker
        │
        └──────────────────┬──────────────────┐
                           │                  │
                           ▼                  ▼
                    🔎 Port Scanner     🌐 URL Analyzer
                                             │
                                             ▼
                                      📄 File Analyzer
                                             │
                                             ▼
                                      📱 APK Analyzer
                                             │
                                             ▼
                                      🦠 VirusTotal
```

---

# 🔒 Security & Ethical Use

This project is created for cybersecurity education, defensive learning, and authorized security testing.

The tools should only be used:

- On systems you own
- In your own laboratory environment
- With explicit authorization
- For educational purposes
- For defensive security analysis

Never use security tools to access, scan, attack, interfere with, or collect information from systems without permission.

### Important

The platform is an educational project and should not be treated as a replacement for professional security tools, malware-analysis environments, or security assessments.

---

# 🎨 User Interface

The platform uses a clean and beginner-friendly interface designed around a:

- Light
- Modern
- Educational
- Cybersecurity-focused

visual style.

The goal is to make cybersecurity concepts understandable to beginners while providing practical demonstrations.

---

# 🌱 Learning Outcomes

Through this project, I am developing practical knowledge of:

- Web application development
- Python programming
- Flask
- HTML
- CSS
- JavaScript
- Cybersecurity fundamentals
- Network fundamentals
- TCP ports
- Port scanning
- Password security
- Phishing concepts
- URL analysis
- File analysis
- APK static analysis
- SHA-256 hashing
- Threat intelligence
- REST APIs
- Git
- GitHub
- Web deployment
- Security-aware application development

---

# 🔮 Future Improvements

Planned improvements include:

- User authentication
- Cybersecurity quizzes
- Security awareness score
- More phishing examples
- Password-security recommendations
- Network-security learning modules
- Interactive cybersecurity challenges
- Security news section
- User progress tracking
- Improved accessibility
- Responsive mobile design
- Expanded APK analysis
- Additional file-analysis capabilities
- More detailed security reports
- Improved logging and audit capabilities

---

# 🚀 Future Vision

The long-term goal of this project is to evolve the platform into a practical cybersecurity learning environment where beginners can learn security concepts through interactive tools and controlled demonstrations.

```text
Cybersecurity Awareness
          ↓
Security Fundamentals
          ↓
Practical Security Tools
          ↓
Threat Analysis
          ↓
Defensive Security Learning
```

---

# 👨‍💻 Author

**Durga Prasad I**

CSE Student | Software Developer | AI & Cybersecurity Enthusiast

---

# 📜 License

This project is intended for educational and cybersecurity-awareness purposes.

Use the included security tools responsibly and only against systems and files that you are authorized to analyze.
