# Contributing Guide

Thanks for your interest in contributing to this CTF writeups collection! This guide will help you add new writeups to the site.

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/GougasseHamza/writeups.git
   cd writeups
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the site locally**
   ```bash
   mkdocs serve
   ```
   Visit `http://127.0.0.1:8000` to see your changes live!

## Adding a New CTF Event

### 1. Create the Event Directory

```bash
mkdir -p docs/ctf-name
```

### 2. Create an Index Page

Create `docs/ctf-name/index.md`:

```markdown
# CTF Name

Brief description of the CTF event.

## Challenges Solved

### Category Name

#### [Challenge Name](challenge-name.md)
**Difficulty:** Easy/Medium/Hard
**Flag:** `FLAG{...}`

Brief description and key techniques.
```

### 3. Add to Navigation

Edit `mkdocs.yml` and add your CTF to the `nav` section:

```yaml
nav:
  - Home: index.md
  - ASIS CTF:
    - Overview: asis-ctf/index.md
    # ... existing entries
  - Your CTF Name:          # Add this
    - Overview: ctf-name/index.md
    - Challenge 1: ctf-name/challenge1.md
  - About: about.md
```

## Adding a New Writeup

### 1. Create the Writeup File

Create `docs/ctf-name/challenge-name.md` with this structure:

```markdown
# Challenge Name

## Challenge Information
- **Name:** Challenge Name
- **Category:** Web/Pwn/Crypto/Reversing/Forensics
- **Difficulty:** Easy/Medium/Hard
- **Points:** 500
- **Flag:** `FLAG{...}`

## Challenge Description
> The challenge description goes here

## Initial Analysis

Describe your initial observations...

## Vulnerability Discovery

Explain how you found the vulnerability...

## Exploitation

### Step 1: Reconnaissance
...

### Step 2: Exploitation
...

## Flag
```
FLAG{...}
```

## Key Takeaways

1. Lesson 1
2. Lesson 2

## References
- [Link 1](https://example.com)
```

### 2. Add to Event Index

Update `docs/ctf-name/index.md` to include your new challenge.

### 3. Update Home Page

Edit `docs/index.md` to feature your latest writeup if desired.

## Writeup Best Practices

### Structure

- **Clear sections** - Use consistent heading hierarchy
- **Code blocks** - Include language identifiers for syntax highlighting
- **Screenshots** - Use sparingly, prefer code/text when possible
- **Working exploits** - Ensure all code is tested and functional

### Code Examples

Use fenced code blocks with language identifiers:

````markdown
```python
import requests
# Your exploit code
```
````

### Admonitions

Use admonitions for important notes:

```markdown
!!! note "Important"
    This is an important note

!!! warning "Security Warning"
    Only test on systems you own or have permission to test

!!! tip "Pro Tip"
    A helpful tip for readers
```

### Tables

Use tables for structured information:

```markdown
| Vulnerability | Location | Impact |
|---------------|----------|--------|
| XSS | /search | High |
```

### Links

- Use descriptive link text
- Link to relevant resources and documentation
- Credit tools and resources used

## Testing Your Changes

### Local Testing

```bash
# Start local server
mkdocs serve

# Build site (check for errors)
mkdocs build --strict
```

### Validation Checklist

- [ ] All links work correctly
- [ ] Code blocks have proper syntax highlighting
- [ ] Images load properly (if used)
- [ ] Navigation structure is correct
- [ ] No build warnings or errors
- [ ] Mobile responsive (test at different screen sizes)

## Commit Guidelines

### Commit Message Format

```
Add [CTF Name] - [Challenge Name] writeup

Brief description of the challenge and techniques used.
```

Example:
```
Add HackTheBox - Busqueda writeup

Python code injection and Git config exploitation challenge.
Features command injection and privilege escalation.
```

### Pull Request Process

1. Create a feature branch: `git checkout -b add-challenge-name`
2. Add your writeup and update navigation
3. Test locally: `mkdocs serve`
4. Commit your changes with a clear message
5. Push and create a pull request
6. Wait for review and deployment

## File Naming Conventions

- **Directories:** lowercase with hyphens (`ctf-name`)
- **Files:** lowercase with hyphens (`challenge-name.md`)
- **Images:** descriptive names (`exploit-flow-diagram.png`)

## Content Guidelines

### What to Include

- ✅ Detailed vulnerability analysis
- ✅ Step-by-step exploitation process
- ✅ Working exploit code
- ✅ Key learning points
- ✅ Defensive measures / fixes

### What to Avoid

- ❌ Excessive screenshots (prefer code/text)
- ❌ Spoilers without warnings
- ❌ Publishing before CTF ends
- ❌ Unformatted or untested code
- ❌ Plagiarized content

## Style Guide

### Tone

- Educational and informative
- Clear and concise
- Beginner-friendly where possible
- Technical but accessible

### Formatting

- Use **bold** for emphasis
- Use `code` for commands, functions, filenames
- Use > blockquotes for challenge descriptions
- Use numbered lists for sequential steps
- Use bullet points for non-sequential items

## Getting Help

- **Questions:** Open an issue on GitHub
- **Bugs:** Report via GitHub Issues
- **Suggestions:** Open a discussion or issue

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (typically MIT or similar).

---

Thank you for contributing! 🎉
