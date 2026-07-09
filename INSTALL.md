# Installing wcag-checker

This guide assumes **zero technical experience**. It walks you from a
fresh computer to a working `wcag-checker` install. Pick the section for
your operating system and follow it top to bottom — every command is
meant to be copy-pasted, and there are checkpoints along the way so you
can confirm each step worked before moving on.

If something goes wrong at a checkpoint, that's the step to share with
whoever helps you — not the final error, but the first checkpoint where
the expected output didn't appear.

**What you'll end up with:** a program called `wcag-checker` that opens a
Firefox window, lets you browse a website normally, and — whenever you
press the audit hotkey (**Ctrl+Alt+A**, or **Ctrl+Option+A** on macOS) —
checks the current page for WCAG 2.2 AA accessibility issues. When you
close the browser, it writes a report (JSON, plain text, Markdown, a
self-contained HTML page, and a manual-review checklist) plus screenshots
of every page you audited.

**A note about keeping your computer clean.** Almost everything this
install needs goes into a single project folder. Inside it, a hidden
subfolder called `.venv/` holds a self-contained copy of Python's package
manager and every package wcag-checker depends on. If you ever decide to
remove the tool, deleting the project folder removes 99% of what was
installed. See [Uninstalling](#uninstalling) at the end for the full
cleanup recipe.

The only things that get installed system-wide are: **Python itself**,
**Git** (for downloading the source), and (on macOS) **Homebrew** as the
installer for the previous two. These are general-purpose tools many
people want anyway — leaving them on your system has no impact.

**You need a real desktop.** wcag-checker opens a *visible* Firefox
window and measures things like keyboard focus and tab order, which only
behave correctly on a normal graphical desktop. It is **not** a headless
or server tool — run it on the computer you're physically sitting in
front of, not over a plain SSH connection.

**Estimated time:** 20–30 minutes for a first install.

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

### Windows step 1 — Install Firefox

You probably already have Firefox. If not:

1. Open your current browser and go to <https://www.mozilla.org/firefox/new/>.
2. Click the big "Download" button.
3. Run the downloaded installer. Accept the defaults.

**Checkpoint:** open the Start menu, type `firefox`, press Enter. A
Firefox window appears. Close it again.

### Windows step 2 — Install Python

1. Go to <https://www.python.org/downloads/windows/>.
2. Click "Latest Python 3 Release" (any 3.12 or newer is required).
3. Scroll to the bottom of that page and download
   "Windows installer (64-bit)".
4. Run the installer. **Important: tick the box "Add python.exe to
   PATH" at the bottom of the first installer screen**, then click
   "Install Now".


**Checkpoint:** open the Start menu, type `cmd`, press Enter. A
black window opens. Type:

```cmd
python --version
```

Press Enter. You should see something like `Python 3.12.5` (it must be
3.12 or newer). If you see "command not found" or "is not recognized",
the PATH checkbox was missed — re-run the installer, tick the box, and
pick "Modify".

> **Tip:** use **cmd**, not PowerShell. PowerShell's default character
> encoding for redirected output (`> file.html`) is UTF-16, which can
> corrupt the HTML reports wcag-checker writes. cmd uses UTF-8 and works
> correctly. (wcag-checker writes reports to files with `--out`, so this
> only matters if you deliberately redirect output with `>`.)

### Windows step 3 — Install Git

Git is the tool that downloads the wcag-checker source code.

1. Go to <https://git-scm.com/download/win>.
2. Download starts automatically.
3. Run the installer. Click "Next" through every screen — the
   defaults are fine.

**Checkpoint:** in your cmd window from before, type:

```cmd
git --version
```

You should see something like `git version 2.45.0.windows.1`.

### Windows step 4 — Download wcag-checker

In cmd (replace `<your-repository-url>` with the address you were given):

```cmd
cd %USERPROFILE%
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

**Checkpoint:** you should now be inside a folder called `wcag-checker`.
Type:

```cmd
dir
```

You should see folders like `leak_inspector`, `tests`, and files like
`README.md` and `pyproject.toml`.

### Windows step 5 — Set up a virtual environment

A "virtual environment" is a sandbox where Python packages get
installed without affecting the rest of your computer. Run:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**Checkpoint:** your cmd prompt should now start with `(.venv)`. That
means the sandbox is active.

### Windows step 6 — Install wcag-checker

Still inside the same cmd window (the prompt should still show
`(.venv)`):

```cmd
pip install -e .
```

Don't forget the dot at the end.

This downloads a handful of small Python packages (selenium,
axe-selenium-python, pillow, and their dependencies). The first time it
can take 1–2 minutes.

**Checkpoint:** when it finishes, type:

```cmd
wcag-checker --help
```

You should see the usage help for the tool.

You're done. Jump to [Verify the install worked](#verify-the-install-worked).

---

## macOS

### macOS step 1 — Install Firefox

You probably already have Firefox. If not:

1. Open Safari and go to <https://www.mozilla.org/firefox/new/>.
2. Click "Download".
3. Open the downloaded `.dmg` file.
4. Drag the Firefox icon into the Applications folder.

**Checkpoint:** open Spotlight (`Cmd + Space`), type `firefox`,
press Enter. A Firefox window appears. Close it again.

### macOS step 2 — Install the developer tools

macOS doesn't ship a usable Python by default. The cleanest way to
fix that is to install Apple's free developer toolkit, then install
Python through Homebrew (a tool that makes installing developer
software easy).

1. Open the Terminal app (Spotlight `Cmd + Space`, type `terminal`,
   press Enter). A black window appears.
2. Paste this and press Enter:

   ```bash
   xcode-select --install
   ```

   A graphical pop-up appears asking to install command line tools.
   Click "Install". This takes 5–10 minutes.

**Checkpoint:** when it's done, run:

```bash
git --version
```

You should see something like `git version 2.39.5`.

### macOS step 3 — Install Homebrew and Python

In the same Terminal window, paste this and press Enter:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

It will prompt for your Mac login password. Type it (the characters
won't appear on screen — that's normal) and press Enter. Then press
Enter again to confirm.

This takes 5–10 minutes. When it finishes, it prints "Next steps"
with two `eval` commands. **Copy and paste those two commands from
your screen** and run them — they make `brew` available in the
current Terminal session.

Then install Python:

```bash
brew install python@3.12
```

**Checkpoint:**

```bash
python3 --version
```

You should see something like `Python 3.12.5` (it must be 3.12 or newer).

### macOS step 4 — Download wcag-checker

Replace `<your-repository-url>` with the address you were given:

```bash
cd ~
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

**Checkpoint:**

```bash
ls
```

You should see `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`, and others.

### macOS step 5 — Set up a virtual environment

A "virtual environment" is a sandbox folder inside the project that
holds every Python package wcag-checker uses. Nothing gets installed
into your system-wide Python — deleting the project folder removes
everything. Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Checkpoint:** your Terminal prompt now starts with `(.venv)`. That
means the sandbox is active.

### macOS step 6 — Install wcag-checker

```bash
pip install -e .
```
Don't forget the dot at the end.

**Checkpoint:**

```bash
wcag-checker --help
```

You should see the usage help for the tool.

Jump to [Verify the install worked](#verify-the-install-worked).

---

## Linux

These instructions cover the two most common Linux families:

- **Debian / Ubuntu / Linux Mint / Pop!\_OS** — uses `apt`.
- **Fedora / Rocky / Alma / RHEL** — uses `dnf`.

If you use Arch / Manjaro / openSUSE / NixOS / something else, you
already know how to translate these. Skim the dependency list and
substitute your distribution's package manager.

### Linux step 1 — Install the system requirements

Open a terminal (often `Ctrl + Alt + T`, or look for "Terminal" in
your applications).

**On Debian / Ubuntu / Mint / Pop!\_OS:**

```bash
sudo apt update
sudo apt install -y firefox python3 python3-venv python3-pip git
```

If `firefox` isn't found (some Ubuntu versions ship Firefox only as
a Snap), use:

```bash
sudo apt install -y firefox-esr
```

**On Fedora / Rocky / Alma / RHEL:**

```bash
sudo dnf install -y firefox python3 python3-pip git
```

**Checkpoint:**

```bash
firefox --version
python3 --version
git --version
```

You should see version numbers for all three. Python needs to be
3.12 or newer.

### Linux step 2 — Download wcag-checker

Replace `<your-repository-url>` with the address you were given:

```bash
cd ~
git clone <your-repository-url> wcag-checker
cd wcag-checker
```

**Checkpoint:**

```bash
ls
```

You should see `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`, and others.

### Linux step 3 — Set up a virtual environment

A "virtual environment" is a sandbox folder inside the project that
holds every Python package wcag-checker uses. Nothing gets installed
into your system-wide Python — deleting the project folder removes
everything. Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Checkpoint:** your prompt now starts with `(.venv)`. That means the
sandbox is active.

### Linux step 4 — Install wcag-checker

```bash
pip install -e .
```
Don't forget the dot at the end.

**Checkpoint:**

```bash
wcag-checker --help
```

You should see the usage help for the tool.

Jump to [Verify the install worked](#verify-the-install-worked).

---

## Verify the install worked

Still in the terminal where your prompt shows `(.venv)`, run:

```bash
wcag-checker https://example.com --out reports/
```

The first time you run it, Selenium downloads a matching `geckodriver`
automatically — that's expected and only happens once.

Then several things should happen:

1. A fresh Firefox window opens, showing `example.com`.
2. You can click around in the browser normally — you're driving it by
   hand.
3. **Press Ctrl+Alt+A** (Ctrl+Option+A on macOS) to audit the current
   page. Your terminal prints a line confirming an audit ran for that
   page.

**To finish: close the Firefox window.** The terminal prints where it
wrote the report, and a `reports/` folder now contains the results.

Open the HTML report to review the findings:

- **Windows:** `start reports\report.html`
- **macOS:** `open reports/report.html`
- **Linux:** `xdg-open reports/report.html`

`example.com` is a tiny page with very few accessibility issues, so the
report will be short. That's expected.

**If you see all of the above:** the install worked.

---

## Common problems

### "command not found: wcag-checker"

Your virtual environment isn't active. Look at your prompt: if it
doesn't start with `(.venv)`, run:

- **Windows cmd:** `.venv\Scripts\activate.bat`
- **macOS / Linux:** `source .venv/bin/activate`

(You need to do this every time you open a new terminal to use the
tool. There's no harm in it — it just tells the terminal where to
find `wcag-checker`.)

### "geckodriver version 0.36.0 might not be compatible…"

A warning, not an error. Selenium has noticed your Firefox is newer
than the bundled geckodriver. In most cases it works anyway. If runs
actually fail, delete the bundled geckodriver and re-run — Selenium
will fetch a matching one:

- **Windows:** delete `.venv\Lib\site-packages\selenium\webdriver\common\linux\geckodriver.exe`.
- **macOS / Linux:** delete `.venv/bin/geckodriver`.

### "ModuleNotFoundError: No module named 'leak_inspector'"

The `pip install -e .` step didn't complete or wasn't run inside the
project folder. Make sure you're in the right folder (`pwd` on
macOS/Linux shows it) and that the virtual environment is active, then
run `pip install -e .` again. Don't forget the dot at the end.

### Firefox opens but immediately closes / never appears

Two common causes:

- **Firefox is the Ubuntu Snap version.** Snap-Firefox cannot be
  driven by Selenium reliably. Install the regular Firefox from
  Mozilla's PPA, or use `firefox-esr` from `apt`.
- **You're running over SSH or on a server without a display.**
  wcag-checker needs a real desktop — it opens a visible window and
  measures keyboard focus behavior, so it cannot run headless. Run it
  on the computer you're physically sitting in front of.

### The audit hotkey does nothing

Make sure the Firefox window that wcag-checker opened has focus (click
into the page first), then press **Ctrl+Alt+A** (Ctrl+Option+A on
macOS). The audit runs against whatever page is currently showing — you
can press it once per page you want checked.

### "permission denied" when running commands

You shouldn't need `sudo` for any wcag-checker command. If you see
permission errors during `pip install`, your virtual environment isn't
active — re-activate it (see the first item in this list).

### My saved HTML report shows `��` and spaces between every letter

Symptom: you redirected output yourself in PowerShell (e.g. with `>`),
and the resulting file opens as garbled text with a `��` at the start.

Cause: PowerShell's `>` writes UTF-16 LE with a byte-order mark by
default. wcag-checker outputs UTF-8. The mismatch corrupts the file.

Fix: use the `--out` option (which writes UTF-8 files directly) instead
of redirecting with `>`, or re-run in **cmd** rather than PowerShell.

### Anything else

When asking for help, include:

1. Your operating system and version (e.g. "Ubuntu 24.04",
   "macOS 14.5", "Windows 11").
2. The first checkpoint above that didn't produce the expected output.
3. The exact text of the error message.

---

## Uninstalling

Everything you did during this install can be undone. Pick the level
of cleanup you want.

### Level 1 — Just remove wcag-checker

This removes the tool, along with every report it wrote. It does **not**
touch Python, Firefox, or Git — keep those if you ever want to reinstall,
or if other software on your computer uses them.

- **Windows (cmd):**

  ```cmd
  cd %USERPROFILE%
  rmdir /s /q wcag-checker
  ```

- **macOS / Linux:**

  ```bash
  cd ~
  rm -rf wcag-checker
  ```

That's the whole wcag-checker footprint: one folder in your home
directory. The virtual environment, the Python packages (`selenium`,
`axe-selenium-python`, `pillow`), and every report — all of it lives
inside that folder.

### Level 2 — Also remove the system tools

Only do this if you're certain no other software needs them.

- **Windows:** open Settings → Apps → Installed apps, find "Python
  3.x" and "Git" in the list, click each one and choose Uninstall.
- **macOS:**

  ```bash
  brew uninstall python@3.12
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
  ```

  The second command also removes Homebrew itself. Apple's command
  line tools (Xcode CLI) can stay — they're harmless.
- **Linux (Debian / Ubuntu / Mint):**

  ```bash
  sudo apt remove --purge python3-venv python3-pip
  ```

  Don't remove `python3` itself or `git` — many parts of your Linux
  desktop rely on them.
- **Linux (Fedora / Rocky / Alma):**

  ```bash
  sudo dnf remove python3-pip
  ```

  Same caveat: don't remove `python3` or `git`.

### Optional — remove the Firefox profile wcag-checker created

If you ran audits with `--profile` pointed at an existing Firefox
profile, wcag-checker used that profile in place. The default behaviour
(no `--profile` flag) uses a fresh temporary profile that the operating
system cleans up automatically — so unless you explicitly used
`--profile`, there's nothing more to remove.