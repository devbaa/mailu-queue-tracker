"""`mailut audit token generate|show` — the collector's shared secret.

The collector requires a token by default, so creating one has to be a single
obvious command rather than a documented incantation with a umask in it.  A
token nobody can generate safely is a token everybody disables.
"""

from __future__ import annotations

import os
import secrets
import stat
import sys

from .util import MailutError, UsageError

# 32 random bytes, hex encoded.  Long enough that no one is tempted to type it
# from memory, short enough to paste into a Rspamd rule on one line.
TOKEN_BYTES = 32


def cmd_generate(args, config) -> int:
    path = config.token_file
    exists = path.exists()
    if exists and getattr(args, "if_missing", False):
        # Used by `make enable`: never disturb a working installation.
        print(f"keeping the existing collector token at {path}")
        return 0
    if exists and not args.force:
        raise UsageError(
            f"{path} already exists.\n"
            "Replacing it would stop Rspamd submitting until its password is "
            "updated too. Use --force if that is what you want, or --if-missing "
            "to leave an existing token alone.\n"
            "Print the current value with: mailut audit token show"
        )

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MailutError(f"cannot create {path.parent}: {exc}") from exc

    token = secrets.token_hex(TOKEN_BYTES)
    # Create the file private from the outset rather than writing it and then
    # tightening the mode: between those two steps it would be readable.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MailutError(f"cannot write {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token + "\n")
        # An existing file keeps its old mode through O_CREAT, so set it.
        os.chmod(path, 0o600)
    except OSError as exc:
        raise MailutError(f"cannot write {path}: {exc}") from exc

    print(f"{'Replaced' if exists else 'Wrote'} the collector token: {path} (mode 0600)")
    print()
    print("Give Rspamd the same value, in the metadata_exporter rule:")
    print()
    print('    user = "mailut";')
    print(f'    password = "{token}";')
    print()
    print("then restart the antispam container and check the wiring:")
    print()
    print("    cd /opt/mailu && docker compose restart antispam")
    print("    mailut audit doctor")
    return 0


def cmd_show(args, config) -> int:
    """Print the token, for pasting into the exporter rule."""
    path = config.token_file
    if not path.exists():
        raise MailutError(
            f"no collector token at {path}: create one with "
            f"`mailut audit token generate`"
        )
    try:
        info = path.stat()
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MailutError(f"cannot read {path}: {exc}") from exc
    if not token:
        raise MailutError(f"{path} is empty; regenerate it with: mailut audit token generate --force")
    if info.st_mode & 0o077:
        print(
            f"warning: {path} is readable by other accounts "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); run: chmod 600 {path}",
            file=sys.stderr,
        )
    # Bare value on stdout so it can be piped; anything explanatory goes to
    # stderr, where it will not end up in a configuration file.
    print(token)
    return 0
