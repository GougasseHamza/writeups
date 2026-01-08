# CTF Writeups

I've been documenting my journey through various Capture The Flag competitions, and this site is where I share what I've learned. Each writeup here represents hours of poking at web applications, reading source code, and sometimes just staring at my screen until something clicks.

## What I Share

When I write about a challenge, I try to capture the whole experience - not just the solution, but the thought process behind it. You'll find detailed vulnerability analysis, the exact steps I took to exploit each flaw, working code that you can actually run, and the security lessons I picked up along the way.

## Recent Challenges

### ASIS CTF

I recently tackled four web exploitation challenges from ASIS CTF. Each one taught me something new about breaking (and hopefully, securing) web applications.

<div class="grid cards" markdown>

-   **Sanchess**

    ---

    A Rick and Morty themed chess game that turned into a lesson about Python expression injection. After the challenge got patched, I had to learn about Unicode normalization bypasses to solve it again.

    [Read the full story](asis-ctf/sanchess.md)

-   **Rick Gallery**

    ---

    Started as a simple image gallery but ended up teaching me about case-sensitive filter bypasses in PHP. Sometimes the simplest vulnerabilities are the easiest to miss.

    [Read the full story](asis-ctf/rick-gallery.md)

-   **ASIS Mail**

    ---

    A microservices-based email app that had more vulnerabilities than I initially expected. I chained together SSRF, path traversal, and IDOR to finally extract the flag.

    [Read the full story](asis-ctf/asis-mail.md)

-   **Bookmarks**

    ---

    This one was tough. A Flask app that taught me how CRLF injection can completely bypass Content Security Policy. The timing had to be perfect to steal the admin's session.

    [Read the full story](asis-ctf/bookmarks.md)

</div>

## Techniques I've Explored

Through these challenges, I've worked with various exploitation techniques. Here's a quick overview:

| Technique | What I Learned | Challenge |
|-----------|----------------|-----------|
| **SSRF** | Making servers request themselves | ASIS Mail |
| **LFI** | Reading files I shouldn't have access to | Rick Gallery |
| **Path Traversal** | Escaping directory restrictions | ASIS Mail |
| **IDOR** | Accessing other users' data | ASIS Mail |
| **Python Sandbox Escape** | Breaking out of restricted Python environments | Sanchess |
| **Unicode Normalization** | Using fullwidth characters to bypass filters | Sanchess |
| **CRLF Injection** | Injecting newlines into HTTP headers | Bookmarks |
| **CSP Bypass** | Circumventing Content Security Policies | Bookmarks |

## How I Write These

I structure each writeup to be useful for learning. I explain the vulnerability type, show where you might see it in real applications, and discuss how to defend against it. I also include working exploit code because I believe seeing something work is the best way to understand it.

## Contributing

If you spot a mistake or have suggestions for improvement, I'd appreciate it if you opened an issue or pull request on [GitHub](https://github.com/GougasseHamza/writeups). I'm always learning and welcome corrections.

---

*Remember: These techniques are for authorized testing only. Never attack systems you don't own or have explicit permission to test.*
