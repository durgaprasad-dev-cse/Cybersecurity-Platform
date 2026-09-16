# 🛡️ Cybersecurity Awareness Platform Kit

A beginner-friendly cybersecurity awareness and learning platform designed to help users understand common cyber threats, practice identifying phishing attacks, create stronger passwords, and learn basic security concepts.

The project combines multiple cybersecurity learning utilities into one simple web platform.

---

## 🎯 Project Objective

The main objective of this project is to promote cybersecurity awareness and help users develop safer digital habits.

The platform provides interactive tools and demonstrations covering:

- Cybersecurity awareness
- Phishing awareness
- Password security
- Strong password generation
- Basic port scanning concepts

---

## 🚀 Features

### 1. 🛡️ Cyber Awareness

Provides educational information about common cybersecurity threats and safe digital practices.

Topics include:

- Cybersecurity basics
- Online safety
- Social engineering
- Phishing
- Password security
- Account protection
- Safe browsing practices

---

### 2. 🎣 Phishing Demo

An educational phishing demonstration designed to help users understand how phishing attacks work.

It helps users recognize suspicious:

- Links
- Messages
- Emails
- Login pages
- Requests for sensitive information

> This feature is intended strictly for cybersecurity education and awareness.

---

### 3. 🔐 Password Strength Checker

Allows users to evaluate the strength of a password.

The password is categorized into:

- Normal
- Medium
- Strong

The purpose is to demonstrate why longer and more complex passwords provide better protection.

---

### 4. 🔑 Strong Password Generator

Generates strong random passwords for users.

The generator is designed to demonstrate the importance of using:

- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Sufficient password length

Default generated password length:

**14 characters**

---

### 5. 🌐 Port Scanner

A basic educational port-scanning utility implemented in Python.

It demonstrates fundamental concepts related to:

- Network ports
- TCP connections
- Open and closed ports
- Network security
- Basic reconnaissance

> Use the port scanner only on systems you own or have explicit permission to test.

---


### 6. 🔎 URL & File Safety Analyzer

The URL & File Safety Analyzer is one of the main security-analysis features of the platform.

It provides two analysis modes:

URL Analysis
     +
File Analysis
🌍 URL Analysis

Users can submit a URL for security analysis.

The analyzer examines the submitted URL and can combine:

Local URL Analysis

The application checks characteristics such as:

HTTPS usage
IP-address-based URLs
Suspicious keywords
URL length
Encoded characters
Suspicious URL patterns
JavaScript-related patterns
Excessive subdomains
The @ character in URLs

These checks are useful for identifying suspicious URL characteristics.

However, URL structure alone cannot determine whether a website is genuinely malicious.

🦠 VirusTotal Integration

To improve URL analysis, the platform integrates with the VirusTotal API.

VirusTotal provides threat-intelligence information gathered from multiple security engines and services.

The application sends the URL to VirusTotal and retrieves its available analysis information.

The resulting information can include:

Malicious detections
Suspicious detections
Harmless detections
Undetected results
Security-vendor detections
Overall analysis verdict

The application then presents the result through its own security-report interface instead of simply redirecting users to an external security website.

Example workflow
User enters URL
       ↓
Flask receives URL
       ↓
Local URL analysis
       ↓
VirusTotal API request
       ↓
Threat intelligence response
       ↓
Result processing
       ↓
Security report
       ↓
User sees verdict
🧠 URL Risk Classification

The application can display classifications such as:

MALICIOUS / PHISHING
SUSPICIOUS
SAFE / CLEAN
UNDETECTED
UNKNOWN
Example

A URL with multiple security-vendor detections can be reported as:

MALICIOUS / PHISHING

while a URL with no reported malicious detections may be presented as:

SAFE / CLEAN

However, a clean or undetected result should not be interpreted as an absolute guarantee that a website is safe.

Threat intelligence changes over time, and no automated scanner can guarantee that every malicious URL will be detected.

📄 File Safety Analysis

The platform also allows users to upload supported files for analysis.

The application:

File Upload
     ↓
Validate file extension
     ↓
Generate temporary filename
     ↓
Save temporarily
     ↓
Analyze file
     ↓
Generate security information
     ↓
Delete temporary file

The application can collect information such as:

Original filename
File extension
File size
SHA-256 hash
Security indicators
Risk classification

Temporary uploaded files are removed after processing.

🔐 SHA-256 File Hashing

The file analyzer can calculate a SHA-256 hash for an uploaded file.

A hash acts as a digital fingerprint of the file.

For example:

File
 ↓
SHA-256 algorithm
 ↓
Unique hash

If the file contents change, its SHA-256 hash will also change.

This concept is commonly used in cybersecurity for:

File identification
Malware research
Integrity verification
Threat intelligence
Incident investigation
🧩 Supported File Types

The current application supports selected file extensions including:

.apk
.pdf
.zip
.txt
.doc
.docx
.jpg
.jpeg
.png
.exe
.dll
.bat
.cmd
.js
.vbs
.ps1
.sh

The application validates the extension before processing the uploaded file.

## 🛠️ Technologies Used

### Frontend

- HTML5
- CSS3
- JavaScript

### Backend

- Python
- Flask

### Cybersecurity Concepts

- Phishing awareness
- Password security
- Network ports
- Basic network scanning
- Cyber hygiene
- Social engineering awareness

### Deployment & Development

- Git
- GitHub
- Render
- Visual Studio Code

---

## 📂 Project Structure

```text
Cybersecurity-Platform-Kit/
│
├── app.py
├── port_scanner.py
├── requirements.txt
│
├── templates/
│   ├── index.html
│   ├── awareness.html
│   └── phishing_demo.html
│
├── static/
│   └── style.css
│
└── README.md

The exact structure may change as the project is developed and improved.

🔄 How the Platform Works
                    USER
                     │
                     ▼
          🛡️ Cyber Awareness
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   🎣 Phishing   🔐 Password   🔑 Password
      Demo         Checker       Generator
                                  │
                                  ▼
                           Strong Password
                                  │
                                  ▼
                         🌐 Port Scanner
🔒 Security & Ethical Use

This project is created for cybersecurity education and ethical learning.

The tools should only be used:

On systems you own
In your own lab environment
With explicit authorization
For educational and defensive purposes

Never use security tools to access, scan, attack, or interfere with systems without permission.

🎨 User Interface

The platform uses a clean and beginner-friendly interface designed around a:

Light
Modern
Educational
Cybersecurity-focused

visual style.

🌱 Learning Outcomes

Through this project, I am developing practical knowledge of:

Web application development
Python programming
Flask
HTML and CSS
Cybersecurity awareness
Network fundamentals
Password security
Phishing concepts
Git and GitHub
Web deployment
🔮 Future Improvements

Planned improvements include:

User authentication
Cybersecurity quizzes
Security awareness score
More phishing examples
Password security recommendations
Network security learning modules
Interactive cybersecurity challenges
Security news section
User progress tracking
Improved accessibility and responsive design