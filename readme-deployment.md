# 🕷️ VulnHunter Pro - Telegram Bot

AI-Powered Vulnerability Scanner with Professional & Halloween-themed HTML Reports

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

## 🎯 Features

- 🔍 **Automated Vulnerability Scanning**
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - IDOR (Insecure Direct Object Reference)
  - CSRF (Cross-Site Request Forgery)
  - SSRF (Server-Side Request Forgery)
  - Security Headers Analysis

- 📊 **Dual Report Formats**
  - Professional Text Report
  - Halloween-themed HTML Report

- 🤖 **Telegram Integration**
  - Easy-to-use bot interface
  - Real-time scan progress
  - Instant report delivery

- ⚡ **Contextual Payloads**
  - AI-generated payloads based on target analysis
  - Ready-to-use test cases
  - Detailed usage instructions

## 📋 Prerequisites

- Python 3.9 or higher
- Telegram account
- Vercel account (for deployment)

## 🚀 Quick Start (Local)

### Step 1: Clone/Download Files

Create a new directory and save these files:
- `main.py` (main bot code)
- `requirements.txt` (dependencies)
- `vercel.json` (deployment config)

### Step 2: Create Telegram Bot

1. Open Telegram and search for [@BotFather](https://t.me/botfather)
2. Send `/newbot` command
3. Choose a name: `VulnHunter Pro Bot`
4. Choose a username: `vulnhunter_pro_bot` (must end with 'bot')
5. Copy the **Bot Token** (looks like: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`)

### Step 3: Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt
```

### Step 4: Configure Bot Token

Edit `main.py` and replace:
```python
BOT_TOKEN = 'YOUR_BOT_TOKEN_HERE'
```

With your actual token:
```python
BOT_TOKEN = '1234567890:ABCdefGHIjklMNOpqrsTUVwxyz'
```

### Step 5: Run Bot Locally

```bash
python main.py
```

You should see:
```
🚀 Starting VulnHunter Pro Telegram Bot...
✅ Bot is running! Press Ctrl+C to stop.
```

### Step 6: Test Your Bot

1. Open Telegram
2. Search for your bot username
3. Send `/start`
4. Try scanning: `/scan https://testphp.vulnweb.com`

## 🌐 Deploy to Vercel

### Method 1: Vercel CLI (Recommended)

**Step 1: Install Vercel CLI**
```bash
npm install -g vercel
```

**Step 2: Login to Vercel**
```bash
vercel login
```

**Step 3: Set Environment Variable**
```bash
vercel env add TELEGRAM_BOT_TOKEN
# Paste your bot token when prompted
```

**Step 4: Deploy**
```bash
vercel --prod
```

Your bot will be deployed! Vercel will give you a URL like:
`https://vulnhunter-pro.vercel.app`

### Method 2: Vercel Dashboard

**Step 1: Push to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/vulnhunter-pro.git
git push -u origin main
```

**Step 2: Import to Vercel**
1. Go to [vercel.com/new](https://vercel.com/new)
2. Click "Import Project"
3. Select your GitHub repository
4. Add Environment Variable:
   - Name: `TELEGRAM_BOT_TOKEN`
   - Value: Your bot token
5. Click "Deploy"

**Step 3: Set Webhook (Important!)**

After deployment, set up Telegram webhook:
```bash
curl -X POST "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=https://your-app.vercel.app"
```

Replace:
- `<YOUR_BOT_TOKEN>` with your actual token
- `your-app.vercel.app` with your Vercel URL

### Method 3: Railway (Alternative)

Railway is easier for long-running Python bots:

**Step 1: Install Railway CLI**
```bash
npm install -g @railway/cli
```

**Step 2: Login and Deploy**
```bash
railway login
railway init
railway up
```

**Step 3: Add Environment Variable**
In Railway dashboard:
1. Go to your project
2. Click "Variables"
3. Add `TELEGRAM_BOT_TOKEN` with your token
4. Redeploy

## 🎮 Bot Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/start` | Start the bot | `/start` |
| `/help` | Show help information | `/help` |
| `/scan <url>` | Scan a target URL | `/scan https://example.com` |

## 📊 Report Examples

### Text Report Output:
```
╔═══════════════════════════════════════════════════════════╗
║           VulnHunter Pro - Security Report                ║
╚═══════════════════════════════════════════════════════════╝

🎯 TARGET INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL: https://example.com
Scan Time: 2024-01-15 14:30:00
Technologies: WordPress, jQuery, PHP
Forms Found: 3
Parameters: 5

📊 VULNERABILITY SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Vulnerabilities: 12
Critical: 2
High: 5
Medium: 5
```

### HTML Report Features:
- 🎃 Halloween-themed dark design with red/black colors
- 💀 Animated skull header
- 📊 Visual stats dashboard
- 🔥 Collapsible vulnerability sections
- 📋 Copy-paste ready payloads
- 📱 Mobile responsive

## 🛠️ Project Structure

```
vulnhunter-pro/
├── main.py              # Main bot code
├── requirements.txt     # Python dependencies
├── vercel.json         # Vercel deployment config
├── README.md           # This file
└── .env                # Environment variables (local only)
```

## 🔒 Security & Legal

### ⚠️ IMPORTANT DISCLAIMER

**Only use this tool on systems you have explicit written permission to test.**

- Unauthorized security testing is **ILLEGAL**
- Always obtain proper authorization before scanning
- Use responsibly and ethically
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Best Practices:
1. ✅ Always get written authorization
2. ✅ Test in controlled environments first
3. ✅ Document all testing activities
4. ✅ Report vulnerabilities responsibly
5. ❌ Never use on production systems without permission
6. ❌ Never share vulnerabilities publicly before disclosure

## 🐛 Troubleshooting

### Bot Not Responding
```bash
# Check if bot is running
curl https://api.telegram.org/bot<YOUR_TOKEN>/getMe

# Check webhook status
curl https://api.telegram.org/bot<YOUR_TOKEN>/getWebhookInfo
```

### Scan Fails
- **CORS Errors**: Some sites block automated tools
- **Rate Limiting**: Target site may be rate limiting requests
- **Firewall**: Site may have WAF/firewall blocking scans
- **SSL Issues**: Try using `http://` instead of `https://`

### Vercel Deployment Issues
```bash
# Check logs
vercel logs

# Redeploy
vercel --prod --force
```

## 📈 Advanced Features (Coming Soon)

- [ ] Active vulnerability exploitation
- [ ] Integration with vulnerability databases (CVE, ExploitDB)
- [ ] Custom payload injection
- [ ] Scheduled scans
- [ ] Multi-target batch scanning
- [ ] Integration with bug bounty platforms
- [ ] PDF report generation
- [ ] Web dashboard

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

## 👨‍💻 Author

Created with 💀 by [Your Name]

## 🔗 Links

- **GitHub**: [github.com/yourusername/vulnhunter-pro](https://github.com/yourusername/vulnhunter-pro)
- **Telegram**: [@vulnhunter_pro_bot](https://t.me/vulnhunter_pro_bot)
- **Issues**: [GitHub Issues](https://github.com/yourusername/vulnhunter-pro/issues)

## ⭐ Support

If you find this tool useful:
- ⭐ Star the repository
- 🐛 Report bugs
- 💡 Suggest features
- 🤝 Contribute code

## 📞 Contact

For questions or support:
- Telegram: @yourusername
- Email: your.email@example.com
- Twitter: @yourhandle

---

**Remember: With great power comes great responsibility. Use ethically! 💀🕷️**
