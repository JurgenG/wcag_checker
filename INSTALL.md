# Installing wcag-checker

Step-by-step install from a fresh machine. Pick your OS section and follow
it top to bottom; each step ends in a checkpoint. If a checkpoint fails,
that step is the one to report.

wcag-checker opens a visible Firefox, audits a page's rendered state for
WCAG 2.2 AA issues, and writes reports (JSON, text, Markdown, HTML) plus a
manual-review checklist and per-finding screenshots. See
[README.md](README.md) for usage.

Everything except Python, Git (and Homebrew on macOS) installs into the
project folder's `.venv/`; deleting the folder removes it. See
[Uninstalling](#uninstalling).

The keyboard/focus checks need a real graphical desktop — run it on a
machine you are sitting at, not a plain SSH session. `--headless` exists
but those checks are less reliable without a display.

---

## Table of contents

- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)
- [Verify the install worked](#verify-the-install-worked)
- [Common problems](#common-problems)
- [Uninstalling](#uninstalling)

---

## Windows

### 1 — Firefox

If not already installed, get it from
<https://www.mozilla.org/firefox/new/> and run the installer with defaults.

Checkpoint: Start menu → type `firefox` → Enter opens a Firefox window.

### 2 — Python

1. <https://www.python.org/downloads/windows/> → "Latest Python 3 Release"
   (3.12 or newer).
2. Download "Windows installer (64-bit)".
3. Run it. **Tick "Add python.exe to PATH"**, then "Install Now".

Checkpoint: open `cmd` and run:

```cmd
python --version
```

Expect `Python 3.12` or newer. "not recognized" means the PATH box was
missed — re-run the installer, choose "Modify", tick the box.

Use **cmd**, not PowerShell: PowerShell's `>` redirection writes UTF-16 and
corrupts the reports. This only matters if you redirect with `>`; `--out`
is unaffected.

### 3 — Git

Install from <https://git-scm.com/download/win> (defaults are fine).

Checkpoint:

```cmd
git --version
```

### 4 — Download wcag-checker

Replace `<your-repository-url>` with the address you were given:

```cmd
cd %USERPROFILE%
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

Checkpoint: `dir` shows `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`.

### 5 — Virtual environment

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

Checkpoint: the prompt now starts with `(.venv)`.

### 6 — Install

```cmd
pip install -e .
```

Note the trailing dot. This pulls in selenium, axe-selenium-python, and
their dependencies (1–2 minutes the first time).

Checkpoint:

```cmd
wcag-checker --help
```

Continue to [Verify the install worked](#verify-the-install-worked).

---

## macOS

### 1 — Firefox

If not already installed: <https://www.mozilla.org/firefox/new/>, open the
`.dmg`, drag Firefox into Applications.

Checkpoint: Spotlight (`Cmd+Space`) → `firefox` → Enter opens Firefox.

### 2 — Command line tools

macOS ships no usable Python by default. Install Apple's command line
tools:

```bash
xcode-select --install
```

Click "Install" in the pop-up (5–10 minutes).

Checkpoint:

```bash
git --version
```

### 3 — Homebrew and Python

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Enter your Mac password when prompted (characters don't show). When it
finishes, run the two `eval` commands it prints under "Next steps", then:

```bash
brew install python@3.12
```

Checkpoint:

```bash
python3 --version
```

Expect 3.12 or newer.

### 4 — Download wcag-checker

```bash
cd ~
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

Checkpoint: `ls` shows `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`.

### 5 — Virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Checkpoint: the prompt now starts with `(.venv)`.

### 6 — Install

```bash
pip install -e .
```

Note the trailing dot. Then:

```bash
wcag-checker --help
```

Continue to [Verify the install worked](#verify-the-install-worked).

---

## Linux

`apt` (Debian / Ubuntu / Mint / Pop!\_OS) and `dnf` (Fedora / Rocky / Alma
/ RHEL) are shown; translate for other distributions.

### 1 — System packages

Debian / Ubuntu / Mint / Pop!\_OS:

```bash
sudo apt update
sudo apt install -y firefox python3 python3-venv python3-pip git
```

If `firefox` isn't found (Snap-only on some Ubuntu releases):

```bash
sudo apt install -y firefox-esr
```

Fedora / Rocky / Alma / RHEL:

```bash
sudo dnf install -y firefox python3 python3-pip git
```

Checkpoint:

```bash
firefox --version
python3 --version
git --version
```

Python must be 3.12 or newer.

### 2 — Download wcag-checker

```bash
cd ~
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

Checkpoint: `ls` shows `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`.

### 3 — Virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Checkpoint: the prompt now starts with `(.venv)`.

### 4 — Install

```bash
pip install -e .
```

Note the trailing dot. Then:

```bash
wcag-checker --help
```

Continue to [Verify the install worked](#verify-the-install-worked).

---

## Verify the install worked

With `(.venv)` active:

```bash
wcag-checker https://example.com --once --out reports/
```

On first run, Selenium downloads a matching `geckodriver` (once). Then
Firefox opens, the page is audited, a summary prints, Firefox closes, and
`reports/` holds the output.

Open the HTML report:

- Windows: `start reports\report.html`
- macOS: `open reports/report.html`
- Linux: `xdg-open reports/report.html`

For interactive audits, drop `--once`, click into the page, press `F9` on
each page you want checked, then close the window:

```bash
wcag-checker https://example.com --out reports/
```

If `F9` clashes with something, pick another with `--hotkey` (e.g.
`--hotkey ctrl+alt+shift+a`). See [README.md](README.md) for all three
run modes.

---

## Common problems

**"wcag-checker: command not found"** — the virtual environment isn't
active (see below) or the install didn't finish. With `(.venv)` showing,
run `pip install -e .` again from inside the project folder.

**Prompt lost its `(.venv)`** — re-activate it (needed in every new
terminal):

- Windows cmd: `.venv\Scripts\activate.bat`
- macOS / Linux: `source .venv/bin/activate`

**"geckodriver … might not be compatible"** — a warning, usually harmless.
If runs actually fail, update Firefox (or geckodriver) so their versions
match, or clear Selenium's cached driver so it re-downloads one.

**"ModuleNotFoundError: No module named 'leak_inspector'"** (or
`'axe_selenium_python'`) — `pip install -e .` didn't complete. With
`(.venv)` active and inside the project folder, run it again (mind the
trailing dot).

**Firefox opens then closes / never appears:**

- Snap Firefox (some Ubuntu releases) can't be driven by Selenium — use
  `firefox-esr` or Mozilla's PPA build.
- No display (SSH / server) — the default and interactive modes need a
  real desktop.

**"permission denied"** — no wcag-checker command needs `sudo`. Permission
errors during `pip install` mean the virtual environment isn't active.

**Saved HTML shows `��` and spaced-out letters** — you redirected output
with PowerShell `>` (UTF-16). Use `--out` (writes UTF-8), or run in cmd.

When asking for help, include your OS and version, the first failed
checkpoint, and the exact error text.

---

## Uninstalling

### Remove wcag-checker

Deletes the tool and every report it wrote; leaves Python, Firefox, and Git.

- Windows (cmd): `cd %USERPROFILE% && rmdir /s /q wcag-checker`
- macOS / Linux: `cd ~ && rm -rf wcag-checker`

Everything (`.venv`, packages, reports) lives in that one folder.

### Also remove the system tools

Only if nothing else needs them.

- Windows: Settings → Apps → Installed apps → uninstall "Python 3.x" and
  "Git".
- macOS:

  ```bash
  brew uninstall python@3.12
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
  ```

- Linux (apt): `sudo apt remove --purge python3-venv python3-pip`
- Linux (dnf): `sudo dnf remove python3-pip`

Don't remove `python3` or `git` themselves — the desktop relies on them.

### Firefox profiles

Each run launches Firefox with a fresh temporary profile that is deleted
when the audit finishes, so there is nothing extra to clean up. To audit
authenticated pages, log in during an interactive (`wcag-checker`) session.
