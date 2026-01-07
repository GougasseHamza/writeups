# CTF Writeups

A collection of detailed Capture The Flag (CTF) challenge writeups and security research.

**🌐 View the site:** [https://GougasseHamza.github.io/writeups/](https://GougasseHamza.github.io/writeups/)

## About

This repository contains detailed writeups for various CTF challenges, featuring:

- 🔍 In-depth vulnerability analysis
- 🛠️ Step-by-step exploitation guides
- 💻 Working exploit code
- 📚 Security lessons and takeaways

## Quick Start

### View Online

Visit the deployed site: **[https://GougasseHamza.github.io/writeups/](https://GougasseHamza.github.io/writeups/)**

### Run Locally

```bash
# Clone the repository
git clone https://github.com/GougasseHamza/writeups.git
cd writeups

# Install dependencies
pip install -r requirements.txt

# Start the local server
mkdocs serve
```

Visit `http://127.0.0.1:8000` in your browser.

## Contents

### ASIS CTF

- **[Sanchess](docs/asis-ctf/sanchess.md)** - Python Expression Injection, Unicode Normalization Bypass
- **[Rick Gallery](docs/asis-ctf/rick-gallery.md)** - Local File Inclusion, Case-Sensitive Filter Bypass
- **[ASIS Mail](docs/asis-ctf/asis-mail.md)** - SSRF, Path Traversal, IDOR
- **[Bookmarks](docs/asis-ctf/bookmarks.md)** - CRLF Injection, HTTP Response Splitting, CSP Bypass

## Techniques Covered

| Category | Techniques |
|----------|------------|
| **Web Exploitation** | SSRF, LFI, Path Traversal, IDOR, XSS |
| **Injection Attacks** | CRLF Injection, Expression Injection, Command Injection |
| **Filter Bypass** | Unicode Normalization, Case Sensitivity, WAF Evasion |
| **Application Security** | CSP Bypass, Authentication Bypass, Session Hijacking |
| **Python Security** | Sandbox Escape, Class Hierarchy Exploitation |

## Contributing

Want to add your own writeup or improve existing ones? Check out the [Contributing Guide](CONTRIBUTING.md) for detailed instructions.

Quick steps:
1. Fork this repository
2. Create a new writeup in `docs/your-ctf-name/`
3. Update `mkdocs.yml` navigation
4. Submit a pull request

## Building the Site

```bash
# Install dependencies
pip install -r requirements.txt

# Build the site
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

## Technology Stack

- **[MkDocs](https://www.mkdocs.org/)** - Static site generator
- **[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)** - Beautiful theme
- **[GitHub Pages](https://pages.github.com/)** - Hosting
- **[GitHub Actions](https://github.com/features/actions)** - Automated deployment

## License

This project is open source. See individual writeups for specific licensing information.

## Disclaimer

⚠️ **Educational Purpose Only**

All techniques and exploits documented in this repository are for **educational purposes only**. Always obtain proper authorization before performing any security testing. Unauthorized access to computer systems is illegal.

---

**Happy Hacking! 🔐**
