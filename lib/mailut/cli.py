"""The `mailut` command line.

One command, a shallow tree of subcommands, real ``--help`` at every level and
the exit codes documented in mailut(8).
"""

from __future__ import annotations

import argparse
import sys

from . import release
from .config import Config, LEVELS
from .events import ACTIONS, STAGES
from .util import EXIT_FAILURE, EXIT_USAGE, MailutError, UsageError

_PARSERS: dict[str, argparse.ArgumentParser] = {}


class _Formatter(argparse.RawDescriptionHelpFormatter):
    """Default values in help, without argparse's cramped column width."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=32, width=100)

    def _get_help_string(self, action):
        text = action.help or ""
        if "%(default)" in text or action.default in (None, False, argparse.SUPPRESS):
            return text
        if action.option_strings and action.nargs != 0:
            return text + " (default: %(default)s)"
        return text


def _add(subparsers, name, help_text, description=None, *, parent_key="", **kwargs):
    parser = subparsers.add_parser(
        name,
        help=help_text,
        description=description or help_text,
        formatter_class=_Formatter,
        **kwargs,
    )
    _PARSERS[(parent_key + " " + name).strip()] = parser
    return parser


# --------------------------------------------------------------------------
# argument groups reused by several commands
# --------------------------------------------------------------------------
def _query_filters(parser: argparse.ArgumentParser, *, with_limit: bool = True) -> None:
    group = parser.add_argument_group("filters")
    group.add_argument("--since", metavar="DURATION|TIME",
                       help="only events at or after this point (e.g. 24h, 7d, 2026-09-01)")
    group.add_argument("--after", metavar="TIME", help="only events at or after this timestamp")
    group.add_argument("--before", metavar="TIME", help="only events strictly before this timestamp")
    group.add_argument("--domain", metavar="DOMAIN", help="recipient domain")
    group.add_argument("--recipient", metavar="EMAIL", help="exact envelope recipient")
    group.add_argument("--sender", metavar="EMAIL", help="exact envelope sender")
    group.add_argument("--sender-domain", metavar="DOMAIN", help="envelope sender domain")
    group.add_argument("--action", action="append", metavar="ACTION", choices=ACTIONS,
                       help=f"classification, repeatable ({', '.join(ACTIONS)})")
    group.add_argument("--stage", action="append", metavar="STAGE", choices=STAGES,
                       help=f"SMTP stage, repeatable ({', '.join(STAGES)})")
    group.add_argument("--queue-id", metavar="ID", help="Postfix queue id")
    group.add_argument("--message-id", metavar="ID", help="RFC822 Message-ID")
    group.add_argument("--ip", metavar="ADDRESS", help="remote client IP")
    group.add_argument("--symbol", metavar="SYMBOL", help="events carrying this Rspamd symbol")
    if with_limit:
        group.add_argument("--limit", type=int, default=100, metavar="N",
                           help="maximum events to print (0 for no limit)")


def _destructive(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="report what would happen and change nothing")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="do not prompt for confirmation")


# --------------------------------------------------------------------------
# parser construction
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=release.COMMAND_NAME,
        description=f"{release.PROJECT_NAME} — queue, abuse and inbound-mail audit tooling for Mailu.",
        formatter_class=_Formatter,
        epilog=(
            "Exit status:\n"
            "  0  success\n"
            "  1  operational or runtime failure\n"
            "  2  invalid command line\n"
            "  3  a destructive action was not confirmed\n"
            "  4  a verification or doctor check failed\n"
            "  5  another lifecycle operation holds the lock\n"
            "\n"
            f"See mailut(8) and mailut.conf(5).  Upstream: {release.UPSTREAM_URL}"
        ),
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    parser.add_argument("-c", "--config", metavar="PATH",
                        help="configuration file (default: /etc/mailut/mailut.conf)")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress non-essential output")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    _PARSERS[""] = parser

    # -- help ---------------------------------------------------------------
    help_parser = _add(sub, "help", "show help for a command")
    help_parser.add_argument("topic", nargs="*", help="command path, e.g. `audit purge`")
    help_parser.set_defaults(func=_cmd_help, needs_config=False)

    # -- version ------------------------------------------------------------
    version_parser = _add(sub, "version", "print the installed version")
    version_parser.add_argument("--json", action="store_true",
                                help="machine-readable output, including the schema version")
    version_parser.set_defaults(func=_cmd_version, needs_config=False)

    # -- status / doctor ----------------------------------------------------
    status_parser = _add(sub, "status", "concise operational status")
    status_parser.add_argument("--json", action="store_true", help="machine-readable output")
    status_parser.set_defaults(func=_lazy("status", "cmd_status"))

    doctor_parser = _add(
        sub, "doctor", "check configuration and dependencies (read-only)",
        "Verify configuration, Docker/Mailu wiring, database, permissions, collector and\n"
        "systemd units. Changes nothing. Exits 4 when a critical check fails.",
    )
    doctor_parser.add_argument("--json", action="store_true", help="machine-readable output")
    doctor_parser.set_defaults(func=_lazy("status", "cmd_doctor"))

    # -- config -------------------------------------------------------------
    config_parser = _add(sub, "config", "inspect the configuration file")
    config_sub = config_parser.add_subparsers(dest="config_command", metavar="SUBCOMMAND")
    check_parser = _add(config_sub, "check", "parse the configuration and report problems",
                        parent_key="config")
    check_parser.set_defaults(func=_cmd_config_check)
    show_parser = _add(config_sub, "show", "print every effective setting", parent_key="config")
    show_parser.add_argument("--json", action="store_true", help="machine-readable output")
    show_parser.set_defaults(func=_cmd_config_show)
    config_parser.set_defaults(func=_cmd_config_show, json=False)

    # -- db -----------------------------------------------------------------
    db_parser = _add(sub, "db", "database maintenance")
    db_sub = db_parser.add_subparsers(dest="db_command", metavar="SUBCOMMAND")
    migrate_parser = _add(db_sub, "migrate", "create or migrate the database schema",
                          parent_key="db")
    migrate_parser.set_defaults(func=_cmd_db_migrate)
    optimize_parser = _add(
        db_sub, "optimize", "run ANALYZE/optimize, and VACUUM only when asked",
        "Maintenance is deliberate: a full VACUUM rewrites the whole database and is\n"
        "never run automatically.",
        parent_key="db",
    )
    optimize_parser.add_argument("--vacuum", action="store_true",
                                 help="also run a full VACUUM (slow; needs free disk space)")
    optimize_parser.set_defaults(func=_cmd_db_optimize)
    db_parser.set_defaults(func=_cmd_db_migrate)

    # -- watch / report -----------------------------------------------------
    watch_parser = _add(
        sub, "watch", "sample queue and SMTP abuse indicators",
        "Take one sample of queue size, delivery outcomes and authenticated sender\n"
        "volume, evaluate it against the [watch] thresholds and record it.\n"
        "Run from mailut-watch.timer; output goes to stdout (journald).",
    )
    watch_parser.add_argument("--print", dest="print_only", action="store_true",
                              help="print the sample without recording it")
    watch_parser.add_argument("--json", action="store_true", help="machine-readable output")
    watch_parser.set_defaults(func=_lazy("watch", "cmd_watch"))

    report_parser = _add(sub, "report", "summarise recorded watch samples")
    report_parser.add_argument("--since", default="7d", metavar="DURATION",
                               help="reporting window")
    report_parser.add_argument("--limit", type=int, default=500, metavar="N",
                               help="maximum samples to consider")
    report_parser.add_argument("--json", action="store_true", help="machine-readable output")
    report_parser.set_defaults(func=_lazy("watch", "cmd_report"))

    # -- ips ----------------------------------------------------------------
    ips_parser = _add(
        sub, "ips", "external client IPs from the Mailu front log",
        "The smtp container only ever sees the front proxy, so a compromised account's\n"
        "real source address lives in the front log. IPv4 only.",
    )
    ips_parser.add_argument("--since", default="24h", metavar="DURATION",
                            help="log window passed to docker compose logs")
    ips_parser.add_argument("--user", metavar="ADDRESS",
                            help="only count lines mentioning this account")
    ips_parser.add_argument("--top", type=int, default=20, metavar="N", help="how many IPs to show")
    ips_parser.add_argument("--all", action="store_true",
                            help="include private/internal addresses")
    ips_parser.add_argument("--exclude", metavar="IP[,IP...]", default="",
                            help="addresses to drop (e.g. your own front IP)")
    ips_parser.add_argument("--json", action="store_true", help="machine-readable output")
    ips_parser.set_defaults(func=_lazy("ips", "cmd_ips"))

    _build_queue(sub)
    _build_audit(sub)
    _build_lifecycle(sub)
    return parser


def _build_queue(sub) -> None:
    queue_parser = _add(
        sub, "queue", "inspect and clean the Postfix queue",
        "Address matching is exact and case-insensitive: example.com never matches\n"
        "user@example.com.",
    )
    queue_sub = queue_parser.add_subparsers(dest="queue_command", metavar="SUBCOMMAND")

    list_parser = _add(queue_sub, "list", "summarise the queue", parent_key="queue")
    list_parser.add_argument("--sender", metavar="EMAIL", help="only messages from this sender")
    list_parser.add_argument("--recipient", metavar="EMAIL", help="only messages to this recipient")
    list_parser.add_argument("--top", type=int, default=10, metavar="N", help="senders to list")
    list_parser.add_argument("--detail", action="store_true", help="list individual messages")
    list_parser.add_argument("--limit", type=int, default=50, metavar="N",
                             help="maximum messages listed with --detail")
    list_parser.add_argument("--json", action="store_true", help="machine-readable output")
    list_parser.set_defaults(func=_lazy("queuecmd", "cmd_list"))

    for name, help_text, description in (
        ("drain", "delete queued messages for one address",
         "Delete every queued message whose envelope sender or recipient is exactly the\n"
         "given address. This does not disable the account: secure it separately."),
        ("hold", "put queued messages for one address on hold",
         "Move matching messages to the hold queue (postsuper -h). Reversible with\n"
         "`mailut queue release`."),
        ("release", "release held messages for one address",
         "Move matching messages out of the hold queue (postsuper -H)."),
    ):
        parser = _add(queue_sub, name, help_text, description, parent_key="queue")
        parser.add_argument("--sender", metavar="EMAIL", help="match the envelope sender")
        parser.add_argument("--recipient", metavar="EMAIL", help="match an envelope recipient")
        parser.add_argument("--limit", type=int, default=20, metavar="N",
                            help="queue ids to list in a dry run")
        _destructive(parser)
        parser.set_defaults(func=_lazy("queuecmd", f"cmd_{name}"))

    queue_parser.set_defaults(
        func=_lazy("queuecmd", "cmd_list"),
        sender=None, recipient=None, top=10, detail=False, limit=50, json=False,
    )


def _build_audit(sub) -> None:
    audit_parser = _add(
        sub, "audit", "inbound mail decision/audit subsystem",
        "Collection is opt-in per recipient scope. `audit remove` stops future\n"
        "collection; only `audit purge` deletes retained evidence.\n"
        "\n"
        "Mail rejected before the SMTP DATA command has no Subject, Message-ID or body,\n"
        "because the sending server had not transmitted them yet. Those fields are\n"
        "reported as unavailable and are never invented.",
    )
    audit_sub = audit_parser.add_subparsers(dest="audit_command", metavar="SUBCOMMAND")

    # add / remove
    add_parser = _add(
        audit_sub, "add", "start collecting for a scope",
        "Ensure a scope is collected. The most specific rule wins (email > domain > all);\n"
        "at equal specificity, exclusion wins.",
        parent_key="audit",
    )
    add_sub = add_parser.add_subparsers(dest="scope_type", metavar="all|domain|email")
    for scope_type, metavar, help_text in (
        ("all", None, "every local recipient"),
        ("domain", "DOMAIN", "every recipient at one domain"),
        ("email", "EMAIL", "one exact envelope recipient"),
    ):
        scope_parser = _add(add_sub, scope_type, help_text, parent_key="audit add")
        if metavar:
            scope_parser.add_argument("value", metavar=metavar, help=help_text)
        scope_parser.add_argument("--retention", type=int, metavar="DAYS",
                                  help="metadata retention for new records (default: audit.default_retention_days)")
        scope_parser.add_argument("--level", choices=LEVELS, metavar="LEVEL",
                                  help=f"collection level: {', '.join(LEVELS)}")
        scope_parser.add_argument("--message-retention", type=int, metavar="DAYS",
                                  help="raw-message retention (only with --level message)")
        scope_parser.set_defaults(func=_lazy("audit", "cmd_add"), scope_type=scope_type,
                                  needs_db=True)

    remove_parser = _add(
        audit_sub, "remove", "stop collecting for a scope",
        "Ensure a scope is NOT collected. This never deletes retained records: existing\n"
        "evidence remains until it expires or `mailut audit purge` removes it.",
        parent_key="audit",
    )
    remove_sub = remove_parser.add_subparsers(dest="scope_type", metavar="all|domain|email")
    for scope_type, metavar, help_text in (
        ("all", None, "every local recipient"),
        ("domain", "DOMAIN", "every recipient at one domain"),
        ("email", "EMAIL", "one exact envelope recipient"),
    ):
        scope_parser = _add(remove_sub, scope_type, help_text, parent_key="audit remove")
        if metavar:
            scope_parser.add_argument("value", metavar=metavar, help=help_text)
        scope_parser.set_defaults(func=_lazy("audit", "cmd_remove"), scope_type=scope_type,
                                  needs_db=True, retention=None, level=None,
                                  message_retention=None)

    scopes_parser = _add(audit_sub, "scopes", "show effective collection scopes", parent_key="audit")
    scopes_parser.add_argument("--test", metavar="EMAIL",
                               help="report whether one address would be collected")
    scopes_parser.add_argument("--json", action="store_true", help="machine-readable output")
    scopes_parser.set_defaults(func=_lazy("audit", "cmd_scopes"), needs_db=True)

    show_parser = _add(
        audit_sub, "show", "search retained events",
        "Absence of a match only means this server holds no matching retained\n"
        "observation for the period; it does not establish what a sending system did.",
        parent_key="audit",
    )
    _query_filters(show_parser)
    show_parser.add_argument("--json", action="store_true",
                             help="one JSON object per line (JSON Lines)")
    show_parser.set_defaults(func=_lazy("query", "cmd_show"), needs_db=True)

    stats_parser = _add(audit_sub, "stats", "counts, storage use and retention span",
                        parent_key="audit")
    _query_filters(stats_parser, with_limit=False)
    stats_parser.add_argument("--json", action="store_true", help="machine-readable output")
    stats_parser.set_defaults(func=_lazy("query", "cmd_stats"), needs_db=True, limit=None)

    purge_parser = _add(
        audit_sub, "purge", "delete retained evidence",
        "Purging is the only operation that deletes audit history. Exactly one selector\n"
        "must be given.",
        parent_key="audit",
    )
    selector = purge_parser.add_argument_group("selectors (choose exactly one)")
    selector.add_argument("--expired", action="store_true",
                          help="records whose retention has elapsed (idempotent)")
    selector.add_argument("--domain", metavar="DOMAIN", help="records for recipients at a domain")
    selector.add_argument("--email", metavar="EMAIL", help="records for one recipient")
    selector.add_argument("--before", metavar="TIME", help="records older than a timestamp")
    selector.add_argument("--all", action="store_true", help="every retained record")
    _destructive(purge_parser)
    purge_parser.add_argument("--json", action="store_true", help="machine-readable output")
    purge_parser.set_defaults(func=_lazy("purge", "cmd_purge"), needs_db=True)

    doctor_parser = _add(audit_sub, "doctor", "check the audit subsystem (read-only)",
                         parent_key="audit")
    doctor_parser.add_argument("--json", action="store_true", help="machine-readable output")
    doctor_parser.set_defaults(func=_lazy("status", "cmd_doctor"))

    collect_parser = _add(
        audit_sub, "collect", "run the audit collector (foreground daemon)",
        "Listens for Rspamd metadata-exporter posts on the configured address and\n"
        "polls the Mailu smtp container log for SMTP evidence. Run by\n"
        "mailut-audit.service; logs to stdout/stderr (journald).\n"
        "\n"
        "Submissions must carry the shared token (mailut audit token generate)\n"
        "unless collector.allow_unauthenticated is set. The bind address must be\n"
        "loopback or the gateway of a Docker bridge network the antispam container\n"
        "is attached to; anything else is refused unless --allow-remote is given.\n"
        "\n"
        "--once opens no socket, so it checks neither of those: it only reads the\n"
        "smtp log.",
        parent_key="audit",
    )
    collect_parser.add_argument("--verbose", action="store_true", help="debug logging")
    collect_parser.add_argument("--once", action="store_true",
                                help="poll the log once and exit (diagnostics)")
    collect_parser.add_argument("--no-log-poll", action="store_true",
                                help="do not read the smtp log; HTTP ingestion only")
    collect_parser.add_argument("--allow-remote", action="store_true",
                                help="permit a wildcard or publicly routable bind address")
    collect_parser.set_defaults(func=_lazy("collector", "cmd_collect"))

    token_parser = _add(
        audit_sub, "token", "manage the collector's shared ingestion token",
        "The collector accepts audit evidence only from a client presenting this\n"
        "token, so that another process on the same network cannot fabricate\n"
        "records. Rspamd sends it as the password of its metadata_exporter rule.",
        parent_key="audit",
    )
    token_sub = token_parser.add_subparsers(dest="token_command", metavar="COMMAND")

    token_generate = _add(
        token_sub, "generate", "create a new random token",
        "Writes a fresh random token to collector.token_file (mode 0600), creating\n"
        "the directory if needed. An existing token is never replaced silently.",
        parent_key="audit token",
    )
    token_generate.add_argument("--force", action="store_true",
                                help="replace an existing token (Rspamd must be updated too)")
    token_generate.add_argument("--if-missing", action="store_true",
                                help="succeed quietly when a token already exists")
    token_generate.set_defaults(func=_lazy("tokencmd", "cmd_generate"))

    token_show = _add(
        token_sub, "show", "print the current token",
        "Prints the token on stdout, for pasting into the exporter rule.",
        parent_key="audit token",
    )
    token_show.set_defaults(func=_lazy("tokencmd", "cmd_show"))

    ingest_parser = _add(
        audit_sub, "ingest", "ingest events from a file or stdin",
        "Replay exporter payloads or Postfix log lines, for testing and manual import.",
        parent_key="audit",
    )
    ingest_parser.add_argument("source", choices=("rspamd", "postfix"), help="payload format")
    ingest_parser.add_argument("--file", default="-", metavar="PATH",
                               help="input file ('-' for stdin)")
    ingest_parser.set_defaults(func=_lazy("collector", "cmd_ingest"))


def _build_lifecycle(sub) -> None:
    upgrade_parser = _add(
        sub, "upgrade", "install a newer public release",
        f"Upgrade from the project's public GitHub releases at {release.UPSTREAM_URL}.\n"
        "No GitHub account or token is needed, and the original source checkout is not\n"
        "required. The release tarball's SHA-256 is always verified; configuration and\n"
        "audit data are preserved.",
    )
    upgrade_parser.add_argument("--check", action="store_true",
                                help="report the available version and exit (no changes, no root)")
    upgrade_parser.add_argument("-n", "--dry-run", action="store_true",
                                help="describe the upgrade without changing anything")
    upgrade_parser.add_argument("--version", dest="target_version", metavar="X.Y.Z",
                                help="install this published release instead of the latest")
    upgrade_parser.add_argument("--allow-downgrade", action="store_true",
                                help="permit installing an older release (schema permitting)")
    upgrade_parser.add_argument("--prerelease", action="store_true",
                                help="consider prereleases (ignored by default)")
    upgrade_parser.add_argument("-y", "--yes", action="store_true",
                                help="do not prompt (for automated deployment)")
    upgrade_parser.add_argument("--verbose", action="store_true", help="show transfer/install detail")
    upgrade_parser.set_defaults(func=_lazy("lifecycle.upgrade", "cmd_upgrade"))

    uninstall_parser = _add(
        sub, "uninstall", "remove the application",
        "Remove the files this application installed, using its own install manifest.\n"
        "Works entirely offline. Configuration and audit data are preserved unless you\n"
        "ask for them to be removed.",
    )
    uninstall_parser.add_argument("--remove-config", action="store_true",
                                  help="also remove /etc/mailut")
    uninstall_parser.add_argument("--remove-data", action="store_true",
                                  help="also remove /var/lib/mailut (destroys retained evidence)")
    uninstall_parser.add_argument("--purge", action="store_true",
                                  help="exactly --remove-config --remove-data, nothing more")
    uninstall_parser.add_argument("-n", "--dry-run", action="store_true",
                                  help="describe the removal without changing anything")
    uninstall_parser.add_argument("-y", "--yes", action="store_true",
                                  help="do not prompt for confirmation")
    uninstall_parser.set_defaults(func=_lazy("lifecycle.uninstall", "cmd_uninstall"))


# --------------------------------------------------------------------------
# command helpers
# --------------------------------------------------------------------------
def _lazy(module: str, attribute: str):
    """Import a command implementation only when it actually runs."""

    def run(args, config, conn=None):
        import importlib

        target = importlib.import_module(f".{module}", __package__)
        function = getattr(target, attribute)
        if getattr(args, "needs_db", False):
            return function(args, config, conn)
        return function(args, config)

    run.module = module
    run.attribute = attribute
    return run


def _cmd_help(args, config=None):
    key = " ".join(args.topic).strip()
    parser = _PARSERS.get(key)
    if parser is None:
        if key:
            print(f"no help for {key!r}", file=sys.stderr)
            print(f"try: {release.COMMAND_NAME} help", file=sys.stderr)
            return EXIT_USAGE
        parser = _PARSERS[""]
    parser.print_help()
    return 0


def _cmd_version(args, config=None):
    if getattr(args, "json", False):
        import json

        from . import migrations

        info = release.buildinfo()
        json.dump(
            {
                "version": info["version"],
                "commit": info["commit"],
                "built_at": info["built_at"],
                "installed": info["installed"],
                # The schema this build knows how to migrate to. `mailut
                # upgrade` reads it from the *newly installed* command, because
                # the upgrading process still has the old release's constants
                # loaded and cannot judge the new one by them.
                "schema_version": migrations.LATEST,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    print(release.version_string())
    return 0


def _cmd_config_check(args, config):
    config.validate()
    print(f"{config.path}: ok" + ("" if config.present else " (file not present; defaults are valid)"))
    return 0


def _cmd_config_show(args, config):
    if getattr(args, "json", False):
        import json

        payload = {}
        for section, key, value in config.items():
            payload.setdefault(section, {})[key] = value
        payload["_derived"] = {
            "state_dir": str(config.state_dir),
            "database": str(config.database),
            "message_dir": str(config.message_dir),
            "backup_dir": str(config.backup_dir),
            "run_dir": str(config.run_dir),
        }
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    print(f"# {config.path}" + ("" if config.present else "  (not present; showing defaults)"))
    current = None
    for section, key, value in config.items():
        if section != current:
            print(f"\n[{section}]")
            current = section
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, list):
            value = ", ".join(value)
        print(f"{key} = {value}")
    return 0


def _cmd_db_migrate(args, config):
    from .db import Database

    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    conn = database.connect()
    try:
        from .db import schema_version

        version = schema_version(conn)
        print(f"{config.database}: schema version {version}")
    finally:
        conn.close()
    return 0


def _cmd_db_optimize(args, config):
    from .db import Database

    database = Database(config.database, config.get("storage", "busy_timeout_ms"))
    conn = database.connect()
    try:
        conn.execute("PRAGMA optimize")
        conn.execute("ANALYZE")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        print("Ran PRAGMA optimize, ANALYZE and a WAL checkpoint.")
        if args.vacuum:
            print("Running VACUUM (this rewrites the whole database)...")
            conn.execute("VACUUM")
            print("VACUUM complete.")
        else:
            print("VACUUM was not run; pass --vacuum to reclaim free pages.")
    finally:
        conn.close()
    return 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if argv and argv[0] in ("-V", "--version"):
        print(release.version_string())
        return 0

    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        print(release.version_string())
        return 0

    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        if not getattr(args, "needs_config", True):
            return args.func(args) or 0

        config = Config.load(args.config)

        if getattr(args, "needs_db", False):
            from .db import Database

            database = Database(config.database, config.get("storage", "busy_timeout_ms"))
            conn = database.connect()
            try:
                return args.func(args, config, conn) or 0
            finally:
                conn.close()
        return args.func(args, config) or 0
    except UsageError as exc:
        print(f"{release.COMMAND_NAME}: {exc}", file=sys.stderr)
        return exc.exit_code
    except MailutError as exc:
        print(f"{release.COMMAND_NAME}: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        # `mailut audit show | head` is a normal thing to do.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_FAILURE
