# auth-log-analyzer

Small Python tool to review Linux authentication logs and get a quick security summary.  
It focuses on SSH login attempts and shows which IPs and usernames are most active.

## Features

- Counts failed SSH logins by source IP and username  
- Counts successful SSH logins by user and IP  
- Works with standard `/var/log/auth.log`-style files

## Requirements

- Python 3.8+
- No external libraries (only the standard library)

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/ngsnethawarya/auth-log-analyzer.git
cd auth-log-analyzer
chmod +x auth_log_analyzer.py
