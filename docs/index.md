# CTF Writeups

Welcome to my collection of Capture The Flag (CTF) challenge writeups! This site contains detailed solutions, exploit code, and security lessons learned from various CTF competitions.

## 🎯 What You'll Find Here

Each writeup includes:

- **Detailed vulnerability analysis** - Understanding the security flaws
- **Step-by-step exploitation** - How to exploit the vulnerabilities
- **Working exploit code** - Complete, tested exploit scripts
- **Key takeaways** - Security lessons and defensive measures

## 📚 Latest Writeups

### ASIS CTF

Four web exploitation challenges featuring advanced techniques:

<div class="grid cards" markdown>

-   :material-chess-knight:{ .lg .middle } **Sanchess**

    ---

    Python expression injection with Unicode normalization bypass

    [:octicons-arrow-right-24: Read more](asis-ctf/sanchess.md)

-   :material-image:{ .lg .middle } **Rick Gallery**

    ---

    PHP LFI through case-sensitive filter bypass

    [:octicons-arrow-right-24: Read more](asis-ctf/rick-gallery.md)

-   :material-email:{ .lg .middle } **ASIS Mail**

    ---

    SSRF + Path Traversal + IDOR vulnerability chain

    [:octicons-arrow-right-24: Read more](asis-ctf/asis-mail.md)

-   :material-bookmark:{ .lg .middle } **Bookmarks**

    ---

    CRLF injection leading to CSP bypass and XSS

    [:octicons-arrow-right-24: Read more](asis-ctf/bookmarks.md)

</div>

## 🛠️ Techniques Covered

The writeups on this site cover a wide range of exploitation techniques:

| Technique | Description | Challenges |
|-----------|-------------|------------|
| **SSRF** | Server-Side Request Forgery | ASIS Mail |
| **LFI** | Local File Inclusion | Rick Gallery |
| **Path Traversal** | Directory traversal attacks | ASIS Mail |
| **IDOR** | Insecure Direct Object Reference | ASIS Mail |
| **Python Sandbox Escape** | Breaking out of restricted Python environments | Sanchess |
| **Unicode Normalization Bypass** | Filter evasion using Unicode characters | Sanchess |
| **CRLF Injection** | HTTP header injection attacks | Bookmarks |
| **CSP Bypass** | Content Security Policy evasion | Bookmarks |
| **XSS** | Cross-Site Scripting | Bookmarks |

## 🎓 Learning Resources

Each writeup is structured to be educational and includes:

- Background on the vulnerability type
- Common real-world occurrences
- Detection methods
- Remediation strategies
- Links to additional resources

## 📬 Contributing

Found a mistake or have suggestions? Feel free to open an issue or submit a pull request on [GitHub](https://github.com/GougasseHamza/writeups).

---

*Happy hacking! Remember: Only perform security testing on systems you own or have explicit permission to test.*
