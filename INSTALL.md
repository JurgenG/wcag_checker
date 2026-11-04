# Installing wcag-checker

This guide takes you from a computer with nothing installed to your first accessibility report. Choose your operating system and follow its steps from top to bottom. Each step ends with a **checkpoint**: a quick test that shows the step worked. If a checkpoint fails, stop there and look at [Common problems](#common-problems).

Allow about 20 minutes. You need an internet connection and permission to install software on the computer.

- [Before you start: the terminal](#before-you-start-the-terminal)
- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)
- [Your first audit](#your-first-audit)
- [Using it again later](#using-it-again-later)
- [Updating to the latest version](#updating-to-the-latest-version)
- [Common problems](#common-problems)
- [Uninstalling](#uninstalling)

---

## Before you start: the terminal

wcag-checker is used by typing commands into a **terminal**: a window where you type a line of text and press **Enter** to run it. This guide shows every command in a grey box. Copy the command, paste it into the terminal, and press Enter. Run one box at a time, and wait until the terminal is ready for the next command before you paste the next one.

How to open a terminal:

- **Windows**: press the **Windows key**, type `cmd`, press **Enter**. A black *Command Prompt* window opens. Use Command Prompt for everything in this guide.
- **macOS**: press **Cmd + Space**, type `terminal`, press **Enter**.
- **Linux**: press **Ctrl + Alt + T**, or open your applications menu and search for *Terminal*.

Pasting: in Command Prompt, right-click inside the window. In macOS Terminal, press **Cmd + V**. In a Linux terminal, press **Ctrl + Shift + V**.

When a command asks for your password, the characters you type are not shown on screen. Type the password and press Enter.

---

## Windows

Works on Windows 10 and Windows 11.

### Step 1 — Install Firefox, Python and Git

Open Command Prompt and run these three commands one by one. Each one downloads and installs a program. If a command asks whether you agree to the terms, type `Y` and press Enter. If Windows asks *"Do you want to allow this app to make changes?"*, click **Yes**.

```cmd
winget install -e --id Mozilla.Firefox
```

```cmd
winget install -e --id Python.Python.3.13
```

```cmd
winget install -e --id Git.Git
```

**Close Command Prompt and open a new one**, so it picks up the newly installed programs.

**Checkpoint:** run

```cmd
python --version
```

```cmd
git --version
```

You should see `Python 3.13.…` and `git version …`.

### Step 2 — Download wcag-checker

This copies the project into a folder called `wcag-checker` inside your user folder (for example `C:\Users\YourName\wcag-checker`):

```cmd
cd %USERPROFILE%
```

```cmd
git clone https://github.com/JurgenG/wcag_checker.git wcag-checker
```

```cmd
cd wcag-checker
```

**Checkpoint:** run `dir`. The list includes `leak_inspector`, `README.md` and `pyproject.toml`.

### Step 3 — Create a virtual environment

A virtual environment is a private space inside the project folder where wcag-checker's components are installed, separate from the rest of your computer.

```cmd
python -m venv .venv
```

```cmd
.venv\Scripts\activate.bat
```

**Checkpoint:** the line where you type now starts with `(.venv)`.

### Step 4 — Install wcag-checker

```cmd
pip install -e .
```

Mind the dot at the end. This takes one or two minutes.

**Checkpoint:** run

```cmd
wcag-checker --help
```

You see a description of the tool and its options. Continue with [Your first audit](#your-first-audit).

---

## macOS

Works on macOS 11 (Big Sur) and newer, on Intel and Apple silicon Macs.

### Step 1 — Install Firefox

1. Go to <https://www.mozilla.org/firefox/new/> and click **Download Firefox**.
2. Open the downloaded `.dmg` file and drag the Firefox icon onto the **Applications** folder.

**Checkpoint:** press **Cmd + Space**, type `firefox`, press **Enter**. Firefox opens. You can close it again.

### Step 2 — Install Git

Open Terminal and run:

```bash
xcode-select --install
```

A window appears asking to install the *command line developer tools*. Click **Install**, accept the license, and wait until it finishes (5 to 15 minutes). If the terminal says the tools are *already installed*, continue to the next step.

**Checkpoint:**

```bash
git --version
```

You see `git version …`.

### Step 3 — Install Python

1. Go to <https://www.python.org/downloads/macos/> and click the **Download Python 3.x** button at the top of the page.
2. Open the downloaded `.pkg` file and click through the installer with the default options.
3. **Quit Terminal (Cmd + Q) and open it again**, so it picks up the new Python.

**Checkpoint:**

```bash
python3 --version
```

You see `Python 3.12` or a higher number.

### Step 4 — Download wcag-checker

This copies the project into a folder called `wcag-checker` in your home folder:

```bash
cd ~
```

```bash
git clone https://github.com/JurgenG/wcag_checker.git wcag-checker
```

```bash
cd wcag-checker
```

**Checkpoint:** run `ls`. The list includes `leak_inspector`, `README.md` and `pyproject.toml`.

### Step 5 — Create a virtual environment

A virtual environment is a private space inside the project folder where wcag-checker's components are installed, separate from the rest of your computer.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

**Checkpoint:** the line where you type now starts with `(.venv)`.

### Step 6 — Install wcag-checker

```bash
pip install -e .
```

Mind the dot at the end. This takes one or two minutes.

**Checkpoint:**

```bash
wcag-checker --help
```

You see a description of the tool and its options. Continue with [Your first audit](#your-first-audit).

---

## Linux

These steps cover Ubuntu 24.04 or newer, Debian 13 or newer and Fedora 40 or newer. These releases include Python 3.12 or newer.

### Step 1 — Install Firefox, Python and Git

Open a terminal and run the commands for your distribution. `sudo` asks for your password.

**Ubuntu 24.04 or newer** (also Linux Mint 22, Pop!_OS 24.04 and other Ubuntu-based systems):

```bash
sudo apt update
```

```bash
sudo apt install -y python3 python3-venv git
```

The Firefox that Ubuntu installs by default is a *Snap* package, which wcag-checker cannot control. Install Mozilla's own Firefox package instead by following the *"Install Firefox .deb package for Debian-based distributions"* section on <https://support.mozilla.org/kb/install-firefox-linux>. Those steps replace the Snap version.

**Debian 13 or newer:**

```bash
sudo apt update
```

```bash
sudo apt install -y firefox-esr python3 python3-venv git
```

**Fedora 40 or newer:**

```bash
sudo dnf install -y firefox python3 git
```

**Checkpoint:**

```bash
python3 --version
```

```bash
git --version
```

You see `Python 3.12` or a higher number, and `git version …`.

### Step 2 — Download wcag-checker

This copies the project into a folder called `wcag-checker` in your home folder:

```bash
cd ~
```

```bash
git clone https://github.com/JurgenG/wcag_checker.git wcag-checker
```

```bash
cd wcag-checker
```

**Checkpoint:** run `ls`. The list includes `leak_inspector`, `README.md` and `pyproject.toml`.

### Step 3 — Create a virtual environment

A virtual environment is a private space inside the project folder where wcag-checker's components are installed, separate from the rest of your computer.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

**Checkpoint:** the line where you type now starts with `(.venv)`.

### Step 4 — Install wcag-checker

```bash
pip install -e .
```

Mind the dot at the end. This takes one or two minutes.

**Checkpoint:**

```bash
wcag-checker --help
```

You see a description of the tool and its options. Continue with [Your first audit](#your-first-audit).

---

## Your first audit

Make sure the line in your terminal starts with `(.venv)`. Then run:

```bash
wcag-checker https://example.com --once
```

The first time, the tool downloads *geckodriver*, a small helper that lets it control Firefox. Then a Firefox window opens, the page is audited, and Firefox closes. The terminal shows the number of findings and the files it wrote.

Open the reports folder:

- Windows: `explorer reports`
- macOS: `open reports`
- Linux: `xdg-open reports`

Open the `example.com` folder and double-click the file ending in `_report.html`. It opens in your browser.

Now try an interactive audit, where you choose the pages yourself:

```bash
wcag-checker https://example.com
```

1. Firefox opens. Browse to any page you want checked.
2. Click once inside the page, then press **F9**. The terminal confirms the audit.
3. Repeat on other pages, then close the Firefox window. The reports are written.

Each run uses a fresh, temporary Firefox profile that is deleted afterwards, so your own Firefox bookmarks and passwords are never touched. To audit pages behind a login, log in inside the Firefox window that wcag-checker opens.

[README.md](README.md) explains all options, the report formats and how to read the results.

---

## Using it again later

Every time you open a new terminal, go to the project folder and activate the virtual environment first.

Windows:

```cmd
cd %USERPROFILE%\wcag-checker
```

```cmd
.venv\Scripts\activate.bat
```

macOS and Linux:

```bash
cd ~/wcag-checker
```

```bash
source .venv/bin/activate
```

When the line starts with `(.venv)`, `wcag-checker` and `wcag-batch` are ready to use.

---

## Updating to the latest version

Go to the project folder and activate the virtual environment as above, then run:

```bash
git pull
```

```bash
pip install -e .
```

---

## Common problems

**`'winget' is not recognized`** (Windows) — open the Microsoft Store, search for *App Installer*, install or update it, then open a new Command Prompt.

**`'python' is not recognized`, or typing `python` opens the Microsoft Store** (Windows) — close Command Prompt and open a new one. If it persists, run the Python `winget install` command from step 1 again.

**`python3 --version` shows 3.9 or lower** (macOS) — quit Terminal completely (Cmd + Q) and open it again. If the number stays low, run the Python installer from step 3 again.

**`wcag-checker: command not found`** or **`'wcag-checker' is not recognized`** — the virtual environment is not active. See [Using it again later](#using-it-again-later).

**`ModuleNotFoundError: No module named 'leak_inspector'`** — the install step did not complete. Activate the virtual environment inside the project folder and run `pip install -e .` again.

**`error: externally-managed-environment`** or **permission denied** during `pip install` — the virtual environment is not active. Activate it and try again. No wcag-checker command needs `sudo`.

**Firefox opens and closes immediately, or never appears** (Linux) — on Ubuntu, check that Mozilla's Firefox package replaced the Snap version (step 1). Run wcag-checker on the computer's own desktop; a remote terminal session has no screen to show Firefox on.

**Pressing F9 does nothing** — click inside the page first so it has keyboard focus. If F9 is used by your system for something else, pick another key, e.g. `wcag-checker https://example.com --hotkey ctrl+alt+shift+a`.

**`geckodriver … might not be compatible`** — usually harmless. If audits fail, update Firefox to the latest version.

When asking for help, include your operating system and version, the step whose checkpoint failed, and the exact error text.

---

## Uninstalling

### Remove wcag-checker

This deletes the tool and every report it wrote. Firefox, Python and Git stay installed.

Windows:

```cmd
cd %USERPROFILE%
```

```cmd
rmdir /s /q wcag-checker
```

macOS and Linux:

```bash
rm -rf ~/wcag-checker
```

### Remove Firefox, Python and Git

Only do this if nothing else on the computer uses them.

- **Windows**: `winget uninstall Python.Python.3.13` and `winget uninstall Git.Git` (and `winget uninstall Mozilla.Firefox`).
- **macOS**: drag Firefox from Applications to the Bin. Python: delete the `Python 3.x` folder in Applications and the folder `/Library/Frameworks/Python.framework/Versions/3.x`. Git comes with the command line developer tools and can stay.
- **Linux**: leave `python3` and `git` installed — your desktop relies on them.
