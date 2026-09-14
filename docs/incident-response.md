# Incident response

Use this when an alert looks like compromised-account or abusive SMTP activity.

## 1. Identify the account

Start with the alert and recent watcher output. Pay particular attention to:

- `top_sasl_sender`
- `top_sasl_count`
- `rate_limit_seen`
- spam/blocklist rejection reasons
- sender queue backlog and recipient-domain fan-out

A single queue spike is not enough by itself to prove account compromise.

## 2. Stop new submissions

Disable the affected Mailu account or rotate its credentials using your normal Mailu administration process.

Do this before relying on queue cleanup. Deleting queued mail does not stop an account from submitting new messages.

## 3. Inspect the queue

Dry-run the exact sender address first:

```bash
sudo mailu-queue-drain.sh --dry-run user@example.com
```

The helper uses exact, case-insensitive envelope-address matching. It exits with an error if the Postfix queue cannot be read, rather than reporting a misleading zero-match result.

## 4. Delete or hold matching mail

Delete matching queued messages:

```bash
sudo mailu-queue-drain.sh user@example.com
```

Or hold them instead:

```bash
sudo mailu-queue-drain.sh --hold user@example.com
```

Recipient matching is available when that is the safer discriminator:

```bash
sudo mailu-queue-drain.sh --dry-run --recipient victim@example.com
sudo mailu-queue-drain.sh --recipient victim@example.com
```

Avoid `postsuper -d ALL` on a multi-tenant server unless deleting the entire queue is explicitly intended.

## 5. Inspect source IPs

Mailu's front proxy may contain the useful external client address:

```bash
sudo mailu-front-ips.sh --since 6h --user user@example.com
```

Treat this as evidence for investigation. Decide on firewall or other network controls using the host's existing operational policy rather than copying a generic firewall command from this repository.

## 6. Preserve evidence

The watcher can save queue and recent log snapshots under:

```text
/var/lib/mailu-queue-watch/snapshots/
```

Preserve the relevant snapshot before deleting it if you need incident review or later forensic analysis. Snapshots contain mail metadata and server logs and should follow the host's retention and access policy.

## 7. Review mail reputation and authentication

After containment, review the remote rejection messages that triggered the alert and verify the server's normal mail-authentication configuration. If a specific blocklist or remote provider rejected the server, follow that provider's current remediation process.

## Automatic containment

The repository intentionally does not automatically disable users or delete queued mail. Those actions can affect legitimate tenants if a threshold is wrong or an incident is misclassified.

Use `ALERT_COMMAND` for notification or carefully reviewed local automation. Keep destructive actions human-confirmed unless you have a separate, tested policy for them.
