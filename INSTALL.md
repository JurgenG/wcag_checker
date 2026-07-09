# Installing leak_inspector

This guide assumes **zero technical experience**. It walks you from a
fresh computer to a working `leak_inspector` install. Pick the section
for your operating system and follow it top to bottom — every command
is meant to be copy-pasted, and there are checkpoints along the way so
you can confirm each step worked before moving on.

If something goes wrong at a checkpoint, that's the step to share with
whoever helps you — not the final error, but the first checkpoint
where the expected output didn't appear.

**What you'll end up with:** a program called `leak_inspector` that
opens a Firefox window, lets you browse a website normally, records
which third-party trackers loaded, and then prints a human-readable
report.

**A note about keeping your computer clean.** Almost everything this
install needs goes into a single folder inside your home directory
(`leak_inspector/`). Inside it, a hidden subfolder called `.venv/`
holds a self-contained copy of Python's package manager and every
package leak_inspector depends on. If you ever decide to remove the
tool, deleting the `leak_inspector/` folder removes 99% of what was
installed. See [Uninstalling](#uninstalling) at the end for the full
cleanup recipe.

The only things that get installed system-wide are: **Python itself**,
**Git** (for downloading the source), and (on macOS) **Homebrew** as
the installer for the previous two. These are general-purpose tools
many people want anyway — leaving them on your system has no impact.

**Estimated time:** 20–30 minutes for a first install.

---

## Table of contents

- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)
- [Verify the install worked](#verify-the-install-worked)
- [Optional: PDF report export](#optional-pdf-report-export)
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
2. Click "Latest Python 3 Release" (any 3.10 or newer is fine).
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

Press Enter. You should see something like `Python 3.12.5`. If you
see "command not found" or "is not recognized", the PATH checkbox
was missed — re-run the installer, tick the box, and pick "Modify".

> **Tip:** use **cmd**, not PowerShell. PowerShell's default
> character encoding for redirected output (`> file.html`) is UTF-16,
> which corrupts the HTML reports leak_inspector writes. cmd uses
> UTF-8 and works correctly. If you already opened PowerShell, close
> it and open cmd instead.

### Windows step 3 — Install Git

Git is the tool that downloads the leak_inspector source code.

1. Go to <https://git-scm.com/download/win>.
2. Download starts automatically.
3. Run the installer. Click "Next" through every screen — the
   defaults are fine.

**Checkpoint:** in your cmd window from before, type:

```cmd
git --version
```

You should see something like `git version 2.45.0.windows.1`.

### Windows step 4 — Download leak_inspector

In cmd:

```cmd
cd %USERPROFILE%
git clone https://codeberg.org/BeLibre/Leak_Detector.git leak_inspector
cd leak_inspector
```

(If your copy comes from a different URL — for example a private
fork — replace the URL above. Whoever sent you the project knows
which one.)

**Checkpoint:** you should now be inside a folder called
`leak_inspector`. Type:

```cmd
dir
```

You should see folders like `leak_inspector`, `tests`, `captures`,
and files like `README.md` and `pyproject.toml`.

### Windows step 5 — Set up a virtual environment

A "virtual environment" is a sandbox where Python packages get
installed without affecting the rest of your computer. Run:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**Checkpoint:** your cmd prompt should now start with `(.venv)`. That
means the sandbox is active.

### Windows step 6 — Install leak_inspector

Still inside the same cmd window (the prompt should still show
`(.venv)`):

```cmd
pip install -e .
```

Don't forget the dot at the end.

This downloads about 20 small Python packages. The first time it can
take 1–2 minutes.

**Checkpoint:** when it finishes, type:

```cmd
leak-inspector --help
```

You should see a list of commands (`capture`, `analyze`, `diff`).

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

You should see something like `Python 3.12.5`.

### macOS step 4 — Download leak_inspector

```bash
cd ~
git clone https://codeberg.org/BeLibre/Leak_Detector.git leak_inspector
cd leak_inspector
```

(Replace the URL if your copy comes from a different source.)

**Checkpoint:**

```bash
ls
```

You should see `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`, and others.

### macOS step 5 — Set up a virtual environment

A "virtual environment" is a sandbox folder inside the project that
holds every Python package leak_inspector uses. Nothing gets installed
into your system-wide Python — deleting the project folder removes
everything. Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Checkpoint:** your Terminal prompt now starts with `(.venv)`. That
means the sandbox is active.

### macOS step 6 — Install leak_inspector

```bash
pip install -e .
```
Don't forget the dot at the end.

**Checkpoint:**

```bash
leak-inspector --help
```

You should see a list of commands.

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
3.10 or newer.

### Linux step 2 — Download leak_inspector

```bash
cd ~
git clone https://codeberg.org/BeLibre/Leak_Detector.git leak_inspector
cd leak_inspector
```

(Replace the URL if your copy comes from a different source.)

**Checkpoint:**

```bash
ls
```

You should see `leak_inspector`, `tests`, `README.md`,
`pyproject.toml`, and others.

### Linux step 3 — Set up a virtual environment

A "virtual environment" is a sandbox folder inside the project that
holds every Python package leak_inspector uses. Nothing gets installed
into your system-wide Python — deleting the project folder removes
everything. Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Checkpoint:** your prompt now starts with `(.venv)`. That means the
sandbox is active.

### Linux step 4 — Install leak_inspector

```bash
pip install -e .
```
Don't forget the dot at the end.

**Checkpoint:**

```bash
leak-inspector --help
```

You should see a list of commands.

Jump to [Verify the install worked](#verify-the-install-worked).

---

## Optional: PDF report export

By default, `leak-inspector analyze` produces a coloured terminal report or
an HTML file. If you also want to export reports as PDF
(`--format pdf`), one extra install step is needed.

PDF export uses **WeasyPrint**, which has two parts:

1. A Python package (installed with pip).
2. A small set of native graphics libraries (cairo, pango, gdk-pixbuf)
   that WeasyPrint uses to draw the page.

### Python package

Make sure your virtual environment is active (prompt shows `(.venv)`), then run:

- **Windows / macOS / Linux:**

  ```bash
  pip install -e '.[pdf]'
  ```

  On **Windows cmd**, use double quotes instead:

  ```cmd
  pip install -e ".[pdf]"
  ```

### Native libraries

**On Debian / Ubuntu / Mint / Pop!\_OS:**

```bash
sudo apt install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
     libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

**On Fedora / Rocky / Alma / RHEL:**

```bash
sudo dnf install -y cairo pango gdk-pixbuf2 libffi
```

**On macOS (Homebrew):**

```bash
brew install cairo pango gdk-pixbuf libffi
```

**On Windows:** install the
[GTK3 runtime for Windows](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)
(the `.exe` installer). Accept the defaults.

### Checkpoint

```bash
leak-inspector analyze captures/test.zip --format pdf --out report.pdf
```

A file `report.pdf` should appear in the current folder and open normally in
a PDF viewer.

---

## Verify the install worked

Still in the terminal where your prompt shows `(.venv)`, run:

```bash
leak-inspector capture https://example.com --out captures/test.zip
```

Three things should happen:

1. A fresh Firefox window opens, showing `example.com`.
2. Your terminal prints lines like `[capture] BiDi subscribed…`.
3. You can click around in the browser. Nothing else captures it —
   only you driving Firefox by hand.

**To finish the capture: close the Firefox window.** The terminal
prints something like `wrote captures/test.zip (16 KB)`.

Now analyze what was captured:

```bash
leak-inspector analyze captures/test.zip
```

You should see a colored, structured report — an executive summary,
a tracker breakdown, and a list of HTTP requests. `example.com` has
almost no trackers, so the report will be short. That's expected.

**If you see all of the above:** the install worked.

---

## Common problems

### "command not found: leak-inspector"

Your virtual environment isn't active. Look at your prompt: if it
doesn't start with `(.venv)`, run:

- **Windows cmd:** `.venv\Scripts\activate.bat`
- **macOS / Linux:** `source .venv/bin/activate`

(You need to do this every time you open a new terminal to use the
tool. There's no harm in it — it just tells the terminal where to
find `leak-inspector`.)

### "geckodriver version 0.36.0 might not be compatible…"

A warning, not an error. Selenium has noticed your Firefox is newer
than the bundled geckodriver. In most cases it works anyway. If
captures actually fail, delete the bundled geckodriver and re-run —
Selenium will fetch a matching one:

- **Windows:** delete `.venv\Lib\site-packages\selenium\webdriver\common\linux\geckodriver.exe`.
- **macOS / Linux:** delete `.venv/bin/geckodriver`.

### "ModuleNotFoundError: No module named 'leak_inspector'"

The `pip install -e .` step didn't complete or wasn't run inside the
`leak_inspector` folder. Make sure you're in the right folder
(`pwd` on macOS/Linux, `pwd` or `cd` on Windows shows it) and that
the virtual environment is active, then run `pip install -e .`
again. Don't forget the dot at the end.

### Firefox opens but immediately closes / never appears

Two common causes:

- **Firefox is the Ubuntu Snap version.** Snap-Firefox cannot be
  driven by Selenium reliably. Install the regular Firefox from
  Mozilla's PPA, or use `firefox-esr` from `apt`.
- **You're running over SSH or in a server without a display.**
  leak_inspector needs a real desktop — it's not a headless tool.
  Run it on the same computer you're physically sitting in front
  of.

### "permission denied" when running commands

You shouldn't need `sudo` for any leak_inspector command. If you
see permission errors during `pip install`, your virtual environment
isn't active — re-activate it (see the first item in this list).

### Windows: my saved HTML report shows `��` and spaces between every letter

Symptom: you ran something like
`leak-inspector analyze bundle.zip --format html > report.html`
in PowerShell, and the resulting file opens as garbled text with a
`��` at the start.

Cause: PowerShell's `>` writes UTF-16 LE with a byte-order mark by
default. leak_inspector outputs UTF-8. The encoding mismatch
corrupts the file.

Fix: re-run the command in **cmd**, not PowerShell. Open the Start
menu, type `cmd`, press Enter. cmd's `>` uses UTF-8 on modern
Windows and the file will open correctly.

### Anything else

Open an issue at <https://codeberg.org/BeLibre/Leak_Detector/issues>
with:

1. Your operating system and version (e.g. "Ubuntu 24.04",
   "macOS 14.5", "Windows 11").
2. The first checkpoint above that didn't produce the expected output.
3. The exact text of the error message.

---

## Uninstalling

Everything you did during this install can be undone. Pick the level
of cleanup you want.

### Level 1 — Just remove leak_inspector

This removes the tool, every captured browsing session, and every
report. It does **not** touch Python, Firefox, or Git — keep those if
you ever want to reinstall, or if other software on your computer
uses them.

- **Windows (cmd):**

  ```cmd
  cd %USERPROFILE%
  rmdir /s /q leak_inspector
  ```

- **macOS / Linux:**

  ```bash
  cd ~
  rm -rf leak_inspector
  ```

That's the whole leak_inspector footprint: one folder in your home
directory. The virtual environment, the Python packages
(`selenium`, `tldextract`, `dnspython`, `maxminddb`), every capture,
every report — all of it lives inside that folder.

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

### Optional — remove the Firefox profile leak_inspector created

If you ran captures with `--profile` pointed at an existing Firefox
profile, leak_inspector wrote cookies and storage into that profile.
The default behaviour (no `--profile` flag) uses a fresh temporary
profile that the operating system cleans up automatically — so unless
you explicitly used `--profile`, there's nothing more to remove.
