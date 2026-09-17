# Mailu Tools (mailut) -- build, test and install.
#
#   make help
#   make test
#   make check
#   sudo make install
#   sudo make enable
#   sudo make uninstall
#   make install DESTDIR=/tmp/mailut-root      # staged install, for inspection
#   make dist                                  # release tarball + SHA256SUMS
#
# Conventional variables: PREFIX, DESTDIR, SYSCONFDIR, LOCALSTATEDIR,
# SYSTEMD_UNIT_DIR.

SHELL          := /bin/sh
PACKAGE        := mailut
VERSION        := $(shell cat VERSION)

PREFIX         ?= /usr/local
DESTDIR        ?=
SYSCONFDIR     ?= /etc
LOCALSTATEDIR  ?= /var
SYSTEMD_UNIT_DIR ?= /etc/systemd/system

SBINDIR        := $(PREFIX)/sbin
LIBDIR         := $(PREFIX)/lib/$(PACKAGE)
DATADIR        := $(PREFIX)/share/$(PACKAGE)
MANDIR         := $(PREFIX)/share/man
CONFDIR        := $(SYSCONFDIR)/$(PACKAGE)
STATEDIR       := $(LOCALSTATEDIR)/lib/$(PACKAGE)
RUNDIR         := /run/$(PACKAGE)

PYTHON         ?= python3
INSTALL        ?= install
INSTALL_PROGRAM := $(INSTALL) -m 0755
INSTALL_DATA    := $(INSTALL) -m 0644

# Skip `systemctl daemon-reload` for a staged install or when the caller
# manages the reload itself (mailut upgrade does).
SKIP_DAEMON_RELOAD ?=

PKG_FILES := $(shell find lib/$(PACKAGE) -name '*.py' | sort)
UNITS     := mailut-audit.service mailut-purge.service mailut-purge.timer \
             mailut-watch.service mailut-watch.timer

.PHONY: help test check lint install install-dirs install-bin install-lib \
        install-data install-man install-units install-config manifest \
        enable disable uninstall dist clean version schema-version

help: ## Show this help
	@echo "Mailu Tools $(VERSION) -- make targets:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  %-18s %s\n", $$1, $$2}'
	@echo
	@echo "Variables: PREFIX=$(PREFIX) SYSCONFDIR=$(SYSCONFDIR) LOCALSTATEDIR=$(LOCALSTATEDIR)"
	@echo "           SYSTEMD_UNIT_DIR=$(SYSTEMD_UNIT_DIR) DESTDIR=$(DESTDIR)"

version: ## Print the release version
	@echo $(VERSION)

schema-version: ## Print the SQLite schema version of this release
	@$(PYTHON) -c "import sys; sys.path.insert(0,'lib'); import mailut.release as r; print(r.SCHEMA_VERSION)"

test: ## Run the test suite (no Mailu server, no network required)
	@$(PYTHON) tests/run.py

check: lint ## Static checks: byte-compile, syntax, unit files, docs
	@echo "checking systemd units..."
	@if command -v systemd-analyze >/dev/null 2>&1; then \
	  for unit in systemd/*.service systemd/*.timer; do \
	    systemd-analyze verify --recursive-errors=no "$$unit" 2>&1 \
	      | grep -v -e 'Unknown key' -e 'not found\.$$' -e '^$$' || true; \
	  done; \
	else echo "  (systemd-analyze not available, skipped)"; fi
	@echo "checking man pages..."
	@for page in man/*.8 man/*.5; do \
	  if command -v mandoc >/dev/null 2>&1; then mandoc -T lint -W warning "$$page" || true; \
	  elif command -v groff >/dev/null 2>&1; then groff -man -Tutf8 -z "$$page" || exit 1; \
	  else echo "  (no man linter available, skipped)"; break; fi; \
	done
	@echo "check: ok"

lint: ## Byte-compile every module and check the launcher
	@$(PYTHON) -m compileall -q lib/$(PACKAGE) tools tests >/dev/null
	@$(PYTHON) -c "import ast,sys; ast.parse(open('bin/mailut').read())"
	@echo "lint: ok"

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
install: install-dirs install-bin install-lib install-data install-man \
         install-units install-config manifest ## Install everything (needs root)
	@if [ -z "$(DESTDIR)" ] && [ -z "$(SKIP_DAEMON_RELOAD)" ] && \
	    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then \
	  systemctl daemon-reload; \
	  echo "systemctl daemon-reload done"; \
	fi
	@echo
	@echo "Installed $(PACKAGE) $(VERSION)."
	@echo "  command:  $(SBINDIR)/$(PACKAGE)"
	@echo "  config:   $(CONFDIR)/$(PACKAGE).conf"
	@echo "  state:    $(STATEDIR)"
	@echo "  manual:   man 8 $(PACKAGE)"
	@echo
	@echo "Services are installed but not enabled. To start collecting:"
	@echo "  sudo systemctl enable --now mailut-audit.service"
	@echo "  sudo systemctl enable --now mailut-purge.timer"
	@echo "  sudo systemctl enable --now mailut-watch.timer"
	@echo "(or: sudo make enable)"

install-dirs:
	$(INSTALL) -d -m 0755 $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBDIR)/$(PACKAGE)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBDIR)/$(PACKAGE)/ingest
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBDIR)/$(PACKAGE)/lifecycle
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DATADIR)
	$(INSTALL) -d -m 0755 $(DESTDIR)$(DATADIR)/rspamd
	$(INSTALL) -d -m 0755 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) -d -m 0755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -d -m 0750 $(DESTDIR)$(CONFDIR)
	$(INSTALL) -d -m 0700 $(DESTDIR)$(STATEDIR)
	$(INSTALL) -d -m 0700 $(DESTDIR)$(STATEDIR)/messages
	$(INSTALL) -d -m 0700 $(DESTDIR)$(STATEDIR)/backups
	$(INSTALL) -d -m 0755 $(DESTDIR)$(SYSTEMD_UNIT_DIR)

install-bin:
	$(INSTALL_PROGRAM) bin/$(PACKAGE) $(DESTDIR)$(SBINDIR)/$(PACKAGE)

install-lib:
	@for file in $(PKG_FILES); do \
	  target="$(DESTDIR)$(LIBDIR)/$${file#lib/}"; \
	  $(INSTALL) -d -m 0755 "$$(dirname "$$target")"; \
	  $(INSTALL_DATA) "$$file" "$$target" || exit 1; \
	done
	$(PYTHON) tools/gen-buildinfo.py \
	  --version "$(VERSION)" \
	  --source-root . \
	  --output "$(DESTDIR)$(LIBDIR)/$(PACKAGE)/buildinfo.json" \
	  --layout prefix=$(PREFIX) \
	  --layout sysconfdir=$(SYSCONFDIR) \
	  --layout localstatedir=$(LOCALSTATEDIR) \
	  --layout sbindir=$(SBINDIR) \
	  --layout libdir=$(LIBDIR) \
	  --layout datadir=$(DATADIR) \
	  --layout mandir=$(MANDIR) \
	  --layout systemd_unit_dir=$(SYSTEMD_UNIT_DIR) \
	  --layout confdir=$(CONFDIR) \
	  --layout statedir=$(STATEDIR) \
	  --layout rundir=$(RUNDIR)

install-data:
	$(INSTALL_DATA) etc/mailut.conf.example $(DESTDIR)$(DATADIR)/mailut.conf.example
	$(INSTALL_DATA) share/rspamd/mailut-exporter.conf $(DESTDIR)$(DATADIR)/rspamd/mailut-exporter.conf
	$(INSTALL_DATA) README.md $(DESTDIR)$(DATADIR)/README.md

install-man:
	$(INSTALL_DATA) man/mailut.8 $(DESTDIR)$(MANDIR)/man8/mailut.8
	$(INSTALL_DATA) man/mailut.conf.5 $(DESTDIR)$(MANDIR)/man5/mailut.conf.5

install-units:
	@for unit in $(UNITS); do \
	  $(INSTALL_DATA) systemd/$$unit $(DESTDIR)$(SYSTEMD_UNIT_DIR)/$$unit || exit 1; \
	done

# Never overwrite an administrator's live configuration.
install-config:
	@if [ -f "$(DESTDIR)$(CONFDIR)/$(PACKAGE).conf" ]; then \
	  echo "keeping existing $(DESTDIR)$(CONFDIR)/$(PACKAGE).conf"; \
	else \
	  $(INSTALL) -m 0640 etc/mailut.conf.example "$(DESTDIR)$(CONFDIR)/$(PACKAGE).conf"; \
	  echo "installed default config $(DESTDIR)$(CONFDIR)/$(PACKAGE).conf"; \
	fi

# The manifest is generated from the tree that was just installed, so the
# Makefile and the application share one file list.
manifest:
	$(PYTHON) tools/gen-manifest.py \
	  --destdir "$(DESTDIR)" \
	  --version "$(VERSION)" \
	  --output "$(DESTDIR)$(DATADIR)/install-manifest.json" \
	  --owned program:$(DESTDIR)$(SBINDIR)/$(PACKAGE) \
	  --owned library:$(DESTDIR)$(LIBDIR)/$(PACKAGE) \
	  --owned data:$(DESTDIR)$(DATADIR)/mailut.conf.example \
	  --owned data:$(DESTDIR)$(DATADIR)/README.md \
	  --owned data:$(DESTDIR)$(DATADIR)/rspamd \
	  --owned man:$(DESTDIR)$(MANDIR)/man8/mailut.8 \
	  --owned man:$(DESTDIR)$(MANDIR)/man5/mailut.conf.5 \
	  $(foreach unit,$(UNITS),--owned unit:$(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(unit)) \
	  $(foreach unit,$(UNITS),--unit $(unit)) \
	  --directory $(LIBDIR)/$(PACKAGE)/ingest \
	  --directory $(LIBDIR)/$(PACKAGE)/lifecycle \
	  --directory $(LIBDIR)/$(PACKAGE) \
	  --directory $(LIBDIR) \
	  --directory $(DATADIR)/rspamd \
	  --directory $(DATADIR) \
	  --preserve $(CONFDIR) \
	  --preserve $(STATEDIR) \
	  --layout prefix=$(PREFIX) \
	  --layout sysconfdir=$(SYSCONFDIR) \
	  --layout localstatedir=$(LOCALSTATEDIR) \
	  --layout sbindir=$(SBINDIR) \
	  --layout libdir=$(LIBDIR) \
	  --layout datadir=$(DATADIR) \
	  --layout mandir=$(MANDIR) \
	  --layout systemd_unit_dir=$(SYSTEMD_UNIT_DIR) \
	  --layout confdir=$(CONFDIR) \
	  --layout statedir=$(STATEDIR) \
	  --layout rundir=$(RUNDIR)

enable: ## Enable and start the collector, purge timer and watch timer
	systemctl enable --now mailut-audit.service
	systemctl enable --now mailut-purge.timer
	systemctl enable --now mailut-watch.timer
	systemctl --no-pager status mailut-audit.service | head -5 || true

disable: ## Stop and disable the units (leaves files installed)
	-systemctl disable --now mailut-watch.timer
	-systemctl disable --now mailut-purge.timer
	-systemctl disable --now mailut-audit.service

# Uses the installed application's own manifest-driven removal, so there is
# only one uninstall implementation. Configuration and audit data are kept.
uninstall: ## Remove installed files; keep /etc/mailut and /var/lib/mailut
	@if [ -x "$(DESTDIR)$(SBINDIR)/$(PACKAGE)" ]; then \
	  MAILUT_ROOT="$(DESTDIR)" $(PYTHON) "$(DESTDIR)$(SBINDIR)/$(PACKAGE)" uninstall --yes; \
	else \
	  echo "$(PACKAGE) is not installed at $(DESTDIR)$(SBINDIR)/$(PACKAGE)"; \
	fi

# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------
dist: ## Build dist/mailut-$(VERSION).tar.gz and dist/SHA256SUMS
	@rm -rf dist/$(PACKAGE)-$(VERSION) dist/$(PACKAGE)-$(VERSION).tar.gz
	@mkdir -p dist/$(PACKAGE)-$(VERSION)
	@git ls-files -z \
	  | tar --null --files-from=- -cf - \
	  | tar -xf - -C dist/$(PACKAGE)-$(VERSION)
	@$(MAKE) --no-print-directory schema-version > dist/$(PACKAGE)-$(VERSION)/SCHEMA_VERSION
	@find dist/$(PACKAGE)-$(VERSION) -name '__pycache__' -type d -prune -exec rm -rf {} +
	@tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2020-01-01' \
	  -czf dist/$(PACKAGE)-$(VERSION).tar.gz -C dist $(PACKAGE)-$(VERSION)
	@rm -rf dist/$(PACKAGE)-$(VERSION)
	@cd dist && sha256sum $(PACKAGE)-$(VERSION).tar.gz > SHA256SUMS
	@echo "dist/$(PACKAGE)-$(VERSION).tar.gz"
	@echo "dist/SHA256SUMS"
	@cat dist/SHA256SUMS

clean: ## Remove build artifacts
	rm -rf dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
