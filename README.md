# Failed Login Detector

A simple SOC-style Python project that detects repeated failed SSH login attempts from a Linux `auth.log` file.

## Overview

This project analyzes SSH authentication failures in a Linux log file and identifies repeated failed login attempts from the same source IP against the same username.

When the failed attempt count reaches a defined threshold, the script prints a SOC-style alert showing:
- Alert ID
- Detection time
- Rule name
- Source IP
- Target user
- Attempt count
- Severity
- Triage note
- Recommended action

## Why This Project Matters

Repeated failed logins can indicate brute-force or password-guessing activity. This type of detection is a common SOC use case because it helps analysts identify suspicious login behavior early.

## Files

- `detector.py` - Main Python detection script
- `auth.log` - Sample Linux authentication log
- `output.png` - Screenshot of the code and terminal output
- `README.md` - Project documentation

## How It Works

The script:
1. Opens the `auth.log` file
2. Searches for failed SSH login entries
3. Extracts the username and source IP address
4. Counts repeated failed attempts
5. Triggers an alert when the threshold is reached

## Detection Logic

- 5 failed attempts or more = alert triggered
- 5 to 9 attempts = `MEDIUM`
- 10 or more attempts = `HIGH`

## Requirements

- Python 3.x
- No external libraries required

## Run the Project

```bash
python3 detector.py
```

## Example Output

```text
==============================================================================
              SECURITY OPERATIONS CENTER - FAILED LOGIN ALERT
==============================================================================
Alert ID        : SOC-FLD-001
Detection Time  : 2026-06-04 02:10:00
Rule Name       : Repeated Failed SSH Logins
Threshold       : 5 failed attempts
------------------------------------------------------------------------------
Source IP          Target User        Attempts   Severity
------------------------------------------------------------------------------
203.0.113.50       admin              5          MEDIUM
------------------------------------------------------------------------------
Total Alerts    : 1
Triage Note     : Investigate source IP, targeted account, and login pattern.
Recommended Act.: Check for brute-force activity, review SSH logs,
                  validate account legitimacy, and block the IP if malicious.
==============================================================================
```

## Sample Log

The included `auth.log` file contains sample failed SSH login attempts so the script can be tested immediately.

## Skills Demonstrated

- Python
- Regular expressions
- Linux log analysis
- Basic SOC detection logic
- Brute-force detection
- Security alert formatting
- Introductory triage workflow

## Future Improvements

- Add timestamp parsing
- Add a sliding time window
- Detect password spraying
- Export alerts to JSON or CSV
- Support Windows Event ID 4625 logs
- Build a simple dashboard view

## Project Structure

```text
failed-login-detector/
├── detector.py
├── auth.log
├── output.png
└── README.md
```

## License

This project can be released under the MIT License.
