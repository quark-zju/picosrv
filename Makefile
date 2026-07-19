SHELL := /bin/sh

BINARY := picosrv
BUILD_TARGET := ./cmd/picosrv
BUILD_OUTPUT := ./$(BINARY)
PREFIX ?= /usr/local/bin
INSTALL_PATH := $(PREFIX)/$(BINARY)
TMP_INSTALL_PATH := $(INSTALL_PATH).new
SYSTEMD_DIR ?= /etc/systemd/system
SERVICE_USER ?= picosrv
SERVICE_GROUP ?= $(SERVICE_USER)
CONFIG_DIR ?= /etc/picosrv
ENV_FILE ?= $(CONFIG_DIR)/picosrv.env
CUSTOM_POLICY := internal/config/custom_local.go
CUSTOM_POLICY_EXAMPLE := examples/custom_local.go.example
FAIL2BAN_FILTER_SOURCES := deploy/fail2ban/filter.d/picosrv.conf deploy/fail2ban/filter.d/picosrv-likely-abuse.conf
FAIL2BAN_JAIL_SOURCES := deploy/fail2ban/jail.d/picosrv.local deploy/fail2ban/jail.d/picosrv-likely-abuse.local
FAIL2BAN_FILTER_DIR ?= /etc/fail2ban/filter.d
FAIL2BAN_JAIL_DIR ?= /etc/fail2ban/jail.d
SUDO ?= sudo

.PHONY: build test install install-secret install-systemd install-fail2ban setup-user config deploy deploy-fail2ban

build:
	go build -o $(BUILD_OUTPUT) $(BUILD_TARGET)

test:
	go test ./...

install: build
	$(SUDO) install -m 755 $(BUILD_OUTPUT) $(TMP_INSTALL_PATH)
	$(SUDO) mv -f $(TMP_INSTALL_PATH) $(INSTALL_PATH)

install-secret:
	$(SUDO) install -d -m 755 $(CONFIG_DIR)
	if [ ! -f $(ENV_FILE) ]; then \
		secret=$$(openssl rand -base64 48); \
		printf 'PICOSRV_HMAC_SECRET=%s\n' "$$secret" | $(SUDO) tee $(ENV_FILE) >/dev/null; \
		$(SUDO) chmod 600 $(ENV_FILE); \
	fi

install-systemd:
	$(SUDO) install -m 644 deploy/systemd/picosrv.service $(SYSTEMD_DIR)/picosrv.service
	$(SUDO) install -m 644 deploy/systemd/picosrv.socket $(SYSTEMD_DIR)/picosrv.socket
	$(SUDO) systemctl daemon-reload

install-fail2ban:
	@if ! command -v fail2ban-client >/dev/null 2>&1; then \
		echo "fail2ban-client is required; install fail2ban first" >&2; \
		exit 1; \
	fi
	$(SUDO) install -d -m 755 $(FAIL2BAN_FILTER_DIR) $(FAIL2BAN_JAIL_DIR)
	$(SUDO) install -m 644 $(FAIL2BAN_FILTER_SOURCES) $(FAIL2BAN_FILTER_DIR)/
	$(SUDO) install -m 644 $(FAIL2BAN_JAIL_SOURCES) $(FAIL2BAN_JAIL_DIR)/

setup-user:
	if ! getent group $(SERVICE_GROUP) >/dev/null; then \
		$(SUDO) groupadd --system $(SERVICE_GROUP); \
	fi
	if ! getent passwd $(SERVICE_USER) >/dev/null; then \
		$(SUDO) useradd --system --gid $(SERVICE_GROUP) --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER); \
	fi

config:
	if [ ! -f $(CUSTOM_POLICY) ]; then \
		cp $(CUSTOM_POLICY_EXAMPLE) $(CUSTOM_POLICY); \
	fi
	EDITOR="$${EDITOR:-vim}" sh -c '"$$EDITOR" "$(CUSTOM_POLICY)"'

deploy: setup-user build install install-secret install-systemd

deploy-fail2ban: install-fail2ban
	$(SUDO) fail2ban-client reload
