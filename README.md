# 🛡️ Scam Protector

A Discord security and moderation bot built with **Python** and **discord.py** to help server administrators monitor suspicious accounts, track risk, generate security alerts, and automate protective actions.

Scam Protector is designed around **multiple risk signals** rather than relying on account age alone.

---

## 🚀 Features

* 🔎 Member risk assessment
* 🧮 Risk scoring system
* 👤 Discord account-age analysis
* 🛡️ Multi-signal security checks
* 🟢 Low-risk classification
* 🟡 Monitoring classification
* 🟠 Suspicious-account classification
* 🚨 High-risk classification
* 📋 Security/audit logging
* 🔐 Private security logs
* 🚨 Private security alerts
* 👥 New-member monitoring
* ⚙️ Per-server configuration
* 📊 Server security statistics
* 💾 Persistent SQLite storage
* 🔧 Configurable security thresholds
* 🤖 Automated moderation responses

---

## 🧠 How It Works

When a member joins a protected server, Scam Protector can evaluate security-related signals associated with the account.

The signals contribute to a risk assessment.

```text
                 New Member
                      │
                      ▼
              Security Analysis
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
     Current Signals        Stored Risk Data
          │                       │
          └───────────┬───────────┘
                      ▼
                 Risk Score
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Monitor      Alert        Ban
       Threshold   Threshold    Threshold
```

The purpose is to avoid making moderation decisions based on a single factor.

---

## 📊 Risk Levels

Scam Protector classifies members according to their estimated risk.

```text
🟢 LOW RISK
        ↓
🟡 MONITOR
        ↓
🟠 SUSPICIOUS
        ↓
🚨 HIGH RISK
```

The thresholds can be configured for each server.

---

## ⚙️ Commands

### `/setup`

Configures Scam Protector for the current Discord server.

The bot can configure the server's security settings and create required security channels when necessary.

---

### `/check`

Checks the security profile of a selected server member.

The command can display:

```text
Account creation date
Account age
Stored risk score
Current risk score
Current security signals
Overall risk classification
```

Example:

```text
🔎 Security Check

Account Age:       14 days
Stored Risk Score: 20
Current Risk:      35

Result:
🟡 MONITOR
```

---

### `/stats`

Displays security statistics for the current server.

Statistics include:

```text
Users monitored
Accounts banned
Security alerts
Monitor threshold
Alert threshold
Ban threshold
Protection status
```

---

## 📸 Project Demonstration

### Bot Online

Demonstrates Scam Protector successfully connecting to Discord, coming online, protecting a server, and synchronizing its commands.

![Scam Protector Bot Online](screenshots/bot-online.png)

---

### Statistics & Security Checks

Demonstrates the `/stats` and `/check` commands, including server statistics, configurable thresholds, account information, risk scoring, and security classification.

![Scam Protector Statistics and Security Checks](screenshots/stats-checks.png)

---

## 🔐 Security Channels

Scam Protector separates public server communication from sensitive security information.

Example server structure:

```text
Discord Server
│
├── #general
│   └── General server notifications
│
├── #scam-logs
│   └── Private security/audit logs
│
└── #security-alerts
    └── Private administrator security alerts
```

Security-related information should not be unnecessarily exposed to ordinary server members.

---

## ⚙️ Configuration

Scam Protector supports server-specific security thresholds.

Example:

```text
Minimum Account Age: 7 days

Monitor Threshold: 30
Alert Threshold:   60
Ban Threshold:     80
```

These values are configurable and should be adjusted according to the requirements and risk tolerance of each server.

---

## 🗄️ Data Storage

Scam Protector uses **SQLite** for persistent application data.

The local database can contain server-specific runtime information such as risk scores and statistics.

Database files are intentionally excluded from Git through `.gitignore`.

```text
*.db
*.sqlite
*.sqlite3
```

This prevents private runtime data from being accidentally published.

---

## 🛠️ Technology Stack

```text
Python 3
discord.py
Discord API
SQLite
Linux
Environment variables
Asynchronous programming
```

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/harkarvog-sec/scam-protector.git
cd scam-protector
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## 🔑 Configuration

Scam Protector requires a Discord bot token.

The token must **not** be placed directly inside the Python source code.

Set it as an environment variable:

```bash
export DISCORD_TOKEN="YOUR_DISCORD_BOT_TOKEN"
```

The application reads the token using:

```python
os.getenv("DISCORD_TOKEN")
```

An example configuration file is provided:

```text
.env.example
```

It contains only a placeholder and does not contain a real credential.

---

## ▶️ Running the Bot

Start Scam Protector with:

```bash
python scam-protector.py
```

A successful startup should display information similar to:

```text
Scam Protector is online!
Protecting X servers.
Synced X commands.
```

---

## 🔒 Security Requirements

The Discord bot requires appropriate permissions to perform its configured security and moderation functions.

Depending on the features enabled, permissions may include:

```text
View Channels
Send Messages
Embed Links
Manage Channels
Manage Roles
Ban Members
```

The bot's role must also be positioned correctly in the Discord role hierarchy for moderation actions to work.

Required Discord gateway intents must be enabled in the Discord Developer Portal.

---

## 🚨 Protecting Secrets

Never commit sensitive information to GitHub.

Do not upload:

```text
.env
Discord bot tokens
API keys
Passwords
Private databases
Private logs
Client credentials
```

The repository includes `.gitignore` rules to help prevent accidental publication of sensitive files.

If a Discord bot token is ever exposed, immediately revoke/regenerate it through the Discord Developer Portal.

---

## 🧪 Development

Check the Python source for syntax errors:

```bash
python -m py_compile scam-protector.py
```

No output means the syntax check completed successfully.

---

## 🗺️ Future Development

Potential improvements include:

```text
Advanced behavioral analysis
Raid detection
Join-rate analysis
Reputation-based scoring
Improved false-positive protection
Configurable security rules
Administrator dashboard
Web-based configuration
Docker deployment
VPS deployment
Structured security reports
Enhanced audit logging
Rate limiting
Multi-server management
Client deployment configuration
```

---

## 🎓 What This Project Demonstrates

This project demonstrates practical experience with:

```text
Python application development
Asynchronous programming
Discord API integration
Event-driven architecture
Security automation
Risk-based decision making
Automated moderation
Access control
Logging and monitoring
Persistent data storage
Environment-based secret management
Server-specific configuration
```

---

## ⚠️ Disclaimer

Scam Protector is intended for legitimate Discord server administration, security monitoring, and authorized security automation.

Automated moderation can produce false positives. Server administrators should configure thresholds carefully and review security decisions where appropriate.

---

## 👨‍💻 Author

**Mishack Victor Chinaza**

**C.E.O — HarkarVOG Security**

Application Security Engineer • Penetration Testing • Security Automation

**Email:** [contact@harkarvogsecurity.com](mailto:contact@harkarvogsecurity.com)

**GitHub:** https://github.com/harkarvog-sec

**LinkedIn:** https://www.linkedin.com/in/mishack-victor-728783358/

**Website:** https://www.harkarvogsecurity.com
