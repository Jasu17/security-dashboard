# Security Dashboard

A web-based Linux log analyzer built with Python and Flask. Upload SSH authentication logs, detect security events, and generate HTML reports — all from a simple browser interface.

---

## Features

- Upload and validate log files (`.log`, `.txt`, `auth.log`, `syslog`)
- Extract key metrics: total lines, events, IPs, and users
- Detect SSH security events:
  - Failed SSH login attempts
  - Successful SSH logins
  - Invalid user access attempts
  - Possible brute force attacks
- Visual dashboard with event distribution chart
- Downloadable HTML security report

---

## Tech Stack

| Layer    | Technology          |
|----------|---------------------|
| Backend  | Python 3.10+, Flask |
| Frontend | HTML, Bootstrap 5   |
| Charts   | Chart.js            |
| Storage  | Local filesystem    |

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-user>/security-dashboard.git
cd security-dashboard
```

### 2. Create virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set your own secret key:
```
SECRET_KEY=your-secret-key-here
```

### 4. Run the application

```bash
python app.py
```

Open your browser at `http://127.0.0.1:5000`

---

## Usage

1. Upload an OpenSSH log file from the home screen
2. The dashboard displays metrics, detected events, and security findings
3. Click **Download Report** to export the analysis as an HTML file

---

## Supported Log Format

This version is optimized for **OpenSSH authentication logs** following the standard Linux syslog format:
```
Jan 10 08:15:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 10 08:20:11 server sshd[1235]: Accepted password for javier from 10.0.0.15 port 22 ssh2
Jan 10 08:21:00 server sshd[1236]: Invalid user admin from 203.0.113.42 port 54321
```

Sample logs for testing: [logpai/loghub — OpenSSH](https://github.com/logpai/loghub)

---

## Project Structure

```
security-dashboard/
├── app.py              # Flask routes and application logic
├── analyzer.py         # Log parsing, event detection, findings
├── requirements.txt
├── .env.example
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   └── report.html
├── static/
│   └── style.css
├── uploads/            # Uploaded log files (not versioned)
└── reports/            # Generated HTML reports (not versioned)
```

---

## Roadmap

| Version | Scope                        | Status      |
|---------|------------------------------|-------------|
| v1.0.0  | OpenSSH log analysis         |  Complete |
| v1.1.0  | Apache access log analysis   |  Planned  |

---

## Out of Scope (MVP)

- User authentication and roles
- Real-time monitoring
- External API integrations
- Docker
- Email or Telegram alerts
- Machine Learning
- SIEM integrations (Wazuh, Elasticsearch)

---

## Author

Javier — Systems Engineering student specializing in cybersecurity and security automation.

[Portfolio](https://Jasu17.github.io)