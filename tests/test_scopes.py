"""Scope semantics: add, remove, precedence, normalisation and validation."""

from helpers import MailutTestCase

from mailut import scopes as scope_store
from mailut.util import UsageError


class ScopeTests(MailutTestCase):
    def add(self, scope_type, value="*", level="metadata", retention=30, message_retention=None):
        return scope_store.upsert_scope(
            self.db(),
            scope_type=scope_type,
            value=scope_store.normalize_target(scope_type, None if scope_type == "all" else value),
            mode="include",
            level=level,
            retention_days=retention,
            message_retention_days=message_retention,
        )[0]

    def remove(self, scope_type, value="*"):
        return scope_store.upsert_scope(
            self.db(),
            scope_type=scope_type,
            value=scope_store.normalize_target(scope_type, None if scope_type == "all" else value),
            mode="exclude",
            level="metadata",
            retention_days=30,
            message_retention_days=None,
        )[0]

    def collected(self, recipient, local_domains=()):
        return scope_store.resolve(self.db(), recipient, local_domains=local_domains) is not None

    # -- add ----------------------------------------------------------------
    def test_add_all(self):
        self.add("all")
        self.assertTrue(self.collected("anyone@example.com"))
        self.assertTrue(self.collected("other@example.org"))

    def test_add_domain(self):
        self.add("domain", "example.com")
        self.assertTrue(self.collected("user@example.com"))
        self.assertFalse(self.collected("user@example.org"))

    def test_add_email(self):
        self.add("email", "john@example.com")
        self.assertTrue(self.collected("john@example.com"))
        self.assertFalse(self.collected("jane@example.com"))

    def test_add_is_idempotent_and_updates(self):
        self.add("domain", "example.com", retention=30)
        scope = self.add("domain", "example.com", retention=365)
        self.assertEqual(scope.retention_days, 365)
        self.assertEqual(len(scope_store.list_scopes(self.db())), 1)

    # -- remove -------------------------------------------------------------
    def test_remove_stops_collection(self):
        self.add("domain", "example.com")
        self.assertTrue(self.collected("user@example.com"))
        self.remove("domain", "example.com")
        self.assertFalse(self.collected("user@example.com"))

    def test_remove_all(self):
        self.add("all")
        self.remove("all")
        self.assertFalse(self.collected("user@example.com"))

    def test_remove_domain_under_all(self):
        """add all + remove one domain: everything except that domain."""
        self.add("all")
        self.remove("domain", "private.example.com")
        self.assertFalse(self.collected("user@private.example.com"))
        self.assertTrue(self.collected("user@example.com"))
        self.assertTrue(self.collected("user@other.example.org"))

    def test_email_overrides_excluded_domain(self):
        self.add("all")
        self.remove("domain", "internal.example.com")
        self.add("email", "monitored@internal.example.com")
        self.assertTrue(self.collected("monitored@internal.example.com"))
        self.assertFalse(self.collected("other@internal.example.com"))
        self.assertTrue(self.collected("user@example.com"))

    def test_excluded_email_inside_included_domain(self):
        self.add("domain", "example.com")
        self.remove("email", "secret@example.com")
        self.assertFalse(self.collected("secret@example.com"))
        self.assertTrue(self.collected("public@example.com"))

    def test_nothing_collected_by_default(self):
        self.assertFalse(self.collected("user@example.com"))

    # -- normalisation and validation ---------------------------------------
    def test_case_is_normalised(self):
        self.add("domain", "EXAMPLE.COM")
        self.assertTrue(self.collected("user@example.com"))
        self.assertTrue(self.collected("USER@EXAMPLE.COM".lower()))
        scope = scope_store.get_scope(self.db(), "domain", "example.com")
        self.assertIsNotNone(scope)

    def test_email_case_is_normalised(self):
        self.add("email", "John@Example.COM")
        scope = scope_store.get_scope(self.db(), "email", "john@example.com")
        self.assertIsNotNone(scope)
        self.assertTrue(self.collected("john@example.com"))

    def test_invalid_domains_are_rejected(self):
        for value in ("", "example", "exa mple.com", "-bad.example.com", "a..b.com", "x" * 300):
            with self.assertRaises(UsageError, msg=value):
                scope_store.normalize_target("domain", value)

    def test_invalid_emails_are_rejected(self):
        for value in ("", "user", "user@", "@example.com", "a@b@example.com", "user@example"):
            with self.assertRaises(UsageError, msg=value):
                scope_store.normalize_target("email", value)

    def test_all_takes_no_value(self):
        with self.assertRaises(UsageError):
            scope_store.normalize_target("all", "example.com")

    def test_domain_requires_a_value(self):
        with self.assertRaises(UsageError):
            scope_store.normalize_target("domain", None)

    # -- local domains ------------------------------------------------------
    def test_all_respects_local_domains(self):
        self.add("all")
        self.assertTrue(self.collected("user@example.com", local_domains=["example.com"]))
        self.assertFalse(self.collected("remote@example.org", local_domains=["example.com"]))

    def test_missing_recipient_uses_the_all_scope(self):
        """A connect-stage reject has no recipient; only `all` can cover it."""
        self.assertFalse(self.collected(None))
        self.add("domain", "example.com")
        self.assertFalse(self.collected(None))
        self.add("all")
        self.assertTrue(self.collected(None))

    def test_scope_levels_and_retention_are_kept(self):
        scope = self.add("email", "legal@example.com", level="headers", retention=365)
        self.assertEqual(scope.level, "headers")
        self.assertEqual(scope.retention_days, 365)
        resolved = scope_store.resolve(self.db(), "legal@example.com")
        self.assertEqual(resolved.level, "headers")
        self.assertEqual(resolved.retention_days, 365)
