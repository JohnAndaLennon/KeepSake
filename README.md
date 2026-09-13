# Keepsake

Keepsake is a command-line password manager with TOTP-based recovery. Vaults are encrypted locally with a master-password-derived key; nothing is ever sent over a network, and there is no cloud component.

## Features

- Store passwords, API keys, SSH credentials, database credentials, environment variables, and freeform notes in a single encrypted vault
- Argon2id key derivation + AES-256-GCM authenticated encryption for the vault file
- Optional TOTP-based recovery using a 12-word BIP39 recovery phrase (no weak PINs) plus a live authenticator code
- Configurable TOTP check frequency for routine vault access — every check, hourly, daily, or recovery-only
- QR code display for fast authenticator app setup, with manual entry always available as a fallback
- Clipboard copy with automatic timed clearing (Windows-safe: no visible console window)
- Password strength scoring and expiry reminders for aging credentials
- Filterable `list` command — view all entries or just one type (passwords, API keys, SSH, etc.)
- No positional vault argument required — vaults are managed automatically in a dedicated `Vaults/` folder

## Installation

```bash
git clone https://github.com/yourusername/keepsake.git
cd keepsake
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Or, once packaged:

```bash
pip install -e .
```

For a `keepsake` command available in every terminal without manually activating a virtual environment, install with [pipx](https://pipx.pypa.io/) instead:

```bash
pipx install --editable .
```

Requires Python 3.10 or later.

## Usage

```
keepsake <command> [args] [--vault <file>]
```

If `--vault`/`-v` is omitted, Keepsake uses a default vault. All vaults are stored in a fixed `Vaults/` folder located next to the installed script, regardless of what directory you run `keepsake` from. Vault files are always saved with a `.vault` extension; if you don't type one, it's appended automatically. If you pass an absolute path or a path containing a directory separator, Keepsake respects it as-is instead of placing it in `Vaults/`.

### Vault commands

| Command | Description |
|---|---|
| `init` | Create a new vault |
| `get <program>` | Copy a stored credential to the clipboard |
| `set [type]` | Add or update an entry (default type: `pass`) |
| `delete <program>` | Delete an entry or account interactively |
| `find` | Search for a program by partial name |
| `list [type]` | List programs and accounts, optionally filtered by entry type |
| `reset` | Change the master password |

### Entry types (used with `set` and `list`)

| Type | Fields |
|---|---|
| `pass` | Program, username, password, optional expiry |
| `api` | Service name, API key, optional endpoint, optional expiry |
| `ssh` | Host/IP, username, port, password or key file path |
| `database` (alias `db`) | Name, host, port, username, password, optional connection string |
| `env` | Environment variable name and value |
| `note` | Freeform label and content (license keys, serials, etc.) |

Running `keepsake set` with no type shows an interactive picker — but only *after* your master password is verified, so a wrong password never reveals the picker. Running `keepsake list` with no type shows every entry; `keepsake list api` shows only API key entries, and so on.

### TOTP recovery commands

| Command | Description |
|---|---|
| `setup-recovery` | Enable TOTP-based recovery for a vault and choose a check-frequency policy |
| `recover` | Recover vault access using your 12-word recovery phrase + a live TOTP code |
| `totp-status` | Show whether recovery is set up, optionally test your phrase and TOTP code |
| `manual-auth` | Re-display the TOTP secret/QR code to re-add it to an authenticator app |

### Examples

```bash
keepsake init                              # Create the default vault in Vaults/
keepsake init --vault work                 # Create Vaults/work.vault
keepsake set pass                          # Add a password to the default vault
keepsake set api                           # Add an API key entry
keepsake get github                        # Retrieve "github" from the default vault
keepsake get github -v work                # Retrieve "github" from work.vault
keepsake list                              # List every entry, all types
keepsake list ssh                          # List only SSH entries
keepsake setup-recovery                    # Enable TOTP recovery on the default vault
keepsake totp-status                       # Confirm your recovery phrase and TOTP still work
```

## How it works

Each vault is a single binary file: a short format header, a random salt, a random nonce, and an AES-256-GCM ciphertext. The encryption key is derived from your master password and the per-vault salt using Argon2id. Nothing about the file's contents — program names, usernames, passwords — is readable without the correct master password. Vault writes are atomic (written to a temp file, then swapped in with an atomic rename), so an interrupted save never corrupts your existing vault.

### TOTP recovery

If you set up TOTP recovery, Keepsake generates a random TOTP secret and a separate 12-word BIP39 recovery phrase. Two things happen with that secret:

1. A copy is stored **inside the main vault itself**, encrypted the same way as everything else (by your master password). This is what allows routine TOTP checks — see below — to only require a 6-digit code, not your recovery phrase.
2. A second copy is stored in a companion `.totp` file next to your vault, encrypted with a key derived from your 12-word recovery phrase (via BIP39 seed derivation). This file contains **no plaintext secrets** — only an opaque encrypted blob. This copy exists specifically for disaster recovery: if you forget your master password entirely, the `.totp` file plus your recovery phrase plus a live TOTP code let you regain access and set a new master password.

The recovery phrase is generated with 128 bits of entropy (12 words) and is displayed once during setup — it is not re-typed for confirmation (see Known Limitations below). Losing both your master password and your recovery phrase means permanent, unrecoverable loss of the vault. There is no backdoor.

### TOTP check frequency

During `setup-recovery`, you choose how often Keepsake should ask for a live TOTP code during normal use, independent of the recovery flow above:

| Mode | Behavior |
|---|---|
| Every password check | A TOTP code is required before every `get`, `set`, `delete`, `list`, `find`, or `reset` |
| Once every hour | A code is required at most once per hour of activity |
| Once every day | A code is required at most once per day |
| Recovery only (default) | No routine TOTP checks — a code is only ever needed during `recover` |

This setting only affects routine access. It has no bearing on the `recover` command, which always requires the recovery phrase and a live code regardless of this setting.

### QR code setup

When setting up or re-displaying a TOTP secret, Keepsake renders a scannable QR code directly in the terminal (via the `qrcode` package) alongside the manual setup key and URI. If `qrcode` isn't installed, or your terminal can't render it legibly, the manual secret and setup instructions are always shown as a fallback — QR display is a convenience, never a requirement.

## Threat model — what this does and doesn't protect against

Being upfront about this matters for a tool that holds your passwords.

**What Keepsake protects against:**
- Someone obtaining a copy of your vault file without your master password (protected by Argon2id + AES-GCM)
- Someone obtaining your `.totp` recovery file without your 12-word recovery phrase (same protection scheme, phrase-derived key)
- Accidental disk-level exposure — vault and `.totp` files are written with owner-only (`0600`) permissions on Linux/macOS
- Crash or power-loss corruption during a save — vault and `.totp` writes are atomic (write-to-temp, then atomic rename)
- Clipboard exposure lingering indefinitely — copied secrets are cleared automatically after a timeout, via a detached background process that runs without a visible window (including on Windows)

**What Keepsake does *not* protect against:**
- A compromised operating system, a keylogger, or malware with access to your terminal session — Keepsake has no defense against secrets being captured as you type them, including your recovery phrase during setup
- An attacker with root/administrator access to the machine while the process is running (secrets exist in process memory in plaintext during use)
- Weak master passwords — strength is checked and enforced at a minimum score, but a determined user can still choose something guessable if they override the warnings
- Shoulder-surfing or physical access to an unlocked terminal session
- Windows-specific file permission hardening — `0600` permissions are POSIX-only; Windows relies on filesystem ACLs and default user-account isolation instead

**Known limitations:**
- Python's string immutability means plaintext secrets (master password, recovery phrase, stored credentials) can persist in memory longer than strictly necessary and are not forcibly zeroed. This is a limitation of the language runtime, not something Keepsake can fully control.
- There is no brute-force lockout on the vault file itself, because a file-embedded attempt counter can't meaningfully stop an offline attacker who can simply copy the file. Brute-force resistance comes entirely from Argon2id's computational cost, not from a lockout mechanism.
- The recovery phrase is displayed once during setup and is **not** re-typed for confirmation. If you transcribe it incorrectly, you won't discover this until you actually need to recover your vault — unless you proactively run `keepsake totp-status` to test it. **Running this check immediately after `setup-recovery` is strongly recommended.**
- The TOTP secret used for routine checks is stored inside the vault, protected only by your master password (not by a separate secret). If your master password is compromised, both your vault and your routine TOTP checks are compromised together — the check-frequency feature is a convenience and light deterrent, not an independent security boundary from your master password.

## Dependencies

| Package | Purpose | Minimum version |
|---|---|---|
| `argon2-cffi` | Argon2id key derivation | 25.1.0 |
| `cryptography` | AES-256-GCM authenticated encryption | 50.0.0 |
| `pyotp` | TOTP generation and verification | 2.9.0 |
| `pyperclip` | Cross-platform clipboard access | 1.9.0 |
| `mnemonic` | BIP39 recovery phrase generation and seed derivation | 0.21 |
| `qrcode` | Optional terminal QR code rendering for TOTP setup | 7.4.2 |

Version floors are chosen deliberately for security reasons (patched CVEs, Python 3.13/3.14 compatibility) where applicable, not just for feature availability. `qrcode` is a soft dependency — Keepsake runs normally without it, falling back to text-only TOTP setup. See `requirements.txt` for details.

## Reporting a security issue

If you find a security vulnerability in Keepsake, please do not open a public GitHub issue. Instead, [contact the maintainer directly / open a private security advisory] so it can be addressed before public disclosure.

## License

MIT — see [LICENSE](LICENSE).
