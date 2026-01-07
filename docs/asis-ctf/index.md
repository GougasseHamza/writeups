# ASIS CTF

ASIS CTF is a renowned international cybersecurity competition organized by the ASIS (Academy for Skills and Information Security) team. Known for challenging and creative problems, ASIS CTF attracts top security researchers and enthusiasts from around the world.

## Competition Overview

ASIS CTF features various categories including:

- Web Exploitation
- Cryptography
- Reverse Engineering
- Forensics
- Network Security

## Challenges Solved

Below are the writeups for challenges I solved from ASIS CTF:

### Web Exploitation

#### [Sanchess](sanchess.md)
**Difficulty:** Medium-Hard
**Flag:** `ASIS{y0u_M2D3_r!cK_@NGRY}`

A Rick and Morty themed chess-like game with a Python expression injection vulnerability. Features two exploitation methods:
- Pre-patch: FileLoader class exploitation
- Post-patch: Unicode normalization bypass

**Key Techniques:**
- Python sandbox escape via class hierarchy
- Boolean-based blind data extraction
- Unicode fullwidth character filter bypass

---

#### [Rick Gallery](rick-gallery.md)
**Difficulty:** Easy-Medium
**Flag:** `ASIS{...}`

A PHP image gallery application with case-sensitive filtering flaws leading to Local File Inclusion.

**Key Techniques:**
- Case-insensitive PHP stream wrapper exploitation
- Filter bypass through case manipulation
- Systematic file enumeration

---

#### [ASIS Mail](asis-mail.md)
**Difficulty:** Medium
**Flag:** `ASIS{M4IL_4S_4_S3RVIC3_15UUUUUUE5_62ee9c3cc5029d4c}`

A microservice-based email application with multiple chained vulnerabilities.

**Key Techniques:**
- Server-Side Request Forgery (SSRF)
- Path traversal in object storage
- Insecure Direct Object Reference (IDOR)
- Information disclosure through other users' attempts

---

#### [Bookmarks](bookmarks.md)
**Difficulty:** Hard
**Flag:** `FLAG{...}`

A Flask bookmark manager with CRLF injection leading to complete CSP bypass.

**Key Techniques:**
- CRLF injection in HTTP headers
- HTTP response splitting
- Content Security Policy (CSP) bypass
- XSS via injected JavaScript
- Session cookie exploitation across windows

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Challenges Solved | 4 |
| Category | Web Exploitation |
| Difficulty Range | Easy → Hard |
| Techniques Covered | 10+ |

## Key Learnings

The ASIS CTF challenges provided excellent learning opportunities in:

1. **Multi-layered exploitation** - Chaining multiple vulnerabilities to achieve the goal
2. **Filter bypass techniques** - Creative ways to evade input validation
3. **Client-side security** - Understanding browser security models and their limitations
4. **Microservice security** - Securing inter-service communication and boundaries

---

*All flags have been redacted where appropriate. These writeups are for educational purposes only.*
