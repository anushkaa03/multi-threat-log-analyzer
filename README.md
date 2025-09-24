# Multi Threat Log Analyzer

A **Windows Log Analyzer** with a Tkinter GUI that detects multiple security threats in system login logs. This tool helps monitor suspicious activities such as brute force attacks, credential stuffing, and unusual login times.

---
## Download & Run

You can download the latest version of the MultiThreatDetector application here:

[Download MultiThreatDetector.exe](https://github.com/anushkaa03/multi-threat-log-analyzer/releases/latest)

### How to Run

1. Download `MultiThreatDetector.exe` from the link above.
2. Double-click the EXE to launch the application.
3. Make sure you have your log files ready to analyze.

⚠️ Note: If you see a security warning, choose "More info" → "Run anyway".
## **Features**

- **Brute Force Detection**  
  Detects multiple failed login attempts from the same IP within 1 minute.

- **Repeated Success After Failures**  
  Alerts when a user successfully logs in after multiple failed attempts within 1 hour.

- **Suspicious Login Times**  
  Detects logins outside regular working hours (default: 9 AM – 6 PM).

- **Credential Stuffing Detection**  
  Detects multiple failed login attempts for the same user from different IPs in a short time window.

---

## **Getting Started**

### **Prerequisites**

- Python 3.7 or later
- Tkinter (usually included with Python)
- Standard Python libraries: `re`, `datetime`, `collections`, `os`

---

### **Running the App**

1. Clone the repository:


git clone https://github.com/anushkaa03/multi-threat-log-analyzer.git
cd multi-threat-log-analyzer


2. Run the application:

python log_analyzer.py


3. Use the GUI to:

Browse and select a log file (.txt or .log)

Set the threshold for failed login attempts

Click Analyze Logs to see alerts and summary

### Sample logs
2025-09-25 01:00:01 192.168.0.10 Failed login
2025-09-25 01:01:01 192.168.0.10 User admin login successful
