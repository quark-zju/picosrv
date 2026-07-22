SHELL := /bin/sh

BINARY := picosrv
BUILD_TARGET := ./cmd/picosrv
BUILD_OUTPUT := ./$(BINARY)
PREFIX ?= /usr/local/bin
INSTALL_PATH := $(PREFIX)/$(BINARY)
TMP_INSTALL_PATH := $(INSTALL_PATH).new
SYSTEMD_DIR ?= /etc/systemd/system
LIBEXEC_DIR ?= /usr/local/libexec
SERVICE_USER ?= picosrv
SERVICE_GROUP ?= $(SERVICE_USER)
CONFIG_DIR ?= /etc/picosrv
ENV_FILE ?= $(CONFIG_DIR)/picosrv.env
NFT_RULES_ENV_FILE ?= $(CONFIG_DIR)/nft-rules.env
CUSTOM_POLICY := internal/config/custom_local.go
CUSTOM_POLICY_EXAMPLE := examples/custom_local.go.example
FAIL2BAN_FILTER_SOURCES := deploy/fail2ban/filter.d/picosrv.conf deploy/fail2ban/filter.d/picosrv-likely-abuse.conf
FAIL2BAN_JAIL_SOURCES := deploy/fail2ban/jail.d/picosrv.local deploy/fail2ban/jail.d/picosrv-likely-abuse.local
FAIL2BAN_FILTER_DIR ?= /etc/fail2ban/filter.d
FAIL2BAN_JAIL_DIR ?= /etc/fail2ban/jail.d
SUDO ?= sudo
PYTHON ?= python3
NFT_RULES_SCRIPT := scripts/nft_rules.py
NFT_RULES_INSTALL_PATH := $(LIBEXEC_DIR)/picosrv-nft-rules
NFT_RULES_SERVICE := picosrv-nft-rules.service
NFT_RULES_TIMER := picosrv-nft-rules.timer

.PHONY: build test test-nft-rules nft-rules install install-secret install-systemd install-fail2ban install-nft-rules setup-user config deploy deploy-fail2ban deploy-nft-rules

build:
	go build -o $(BUILD_OUTPUT) $(BUILD_TARGET)

test:
	go test ./...

test-nft-rules:
	PYTHONPYCACHEPREFIX=/tmp/picosrv-pycache $(PYTHON) -m unittest discover -s scripts -p '*_test.py'

nft-rules:
	CC="$${CC:-CN US}" $(PYTHON) $(NFT_RULES_SCRIPT)

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

install-nft-rules:
	@if ! command -v location >/dev/null 2>&1; then \
		echo "location is required; install libloc-tools first" >&2; \
		exit 1; \
	fi
	@if ! command -v nft >/dev/null 2>&1; then \
		echo "nft is required; install nftables first" >&2; \
		exit 1; \
	fi
	@if ! command -v $(PYTHON) >/dev/null 2>&1; then \
		echo "$(PYTHON) is required" >&2; \
		exit 1; \
	fi
	$(SUDO) install -d -m 755 $(CONFIG_DIR) $(LIBEXEC_DIR)
	@if [ ! -f $(NFT_RULES_ENV_FILE) ]; then \
		country_codes="$${CC:-CN US}"; \
		for country_code in $$country_codes; do \
			case "$$country_code" in \
				[a-zA-Z][a-zA-Z]) ;; \
				*) echo "invalid country code: $$country_code" >&2; exit 1 ;; \
			esac; \
		done; \
		printf 'CC="%s"\n' "$$country_codes" | $(SUDO) tee $(NFT_RULES_ENV_FILE) >/dev/null; \
		$(SUDO) chmod 644 $(NFT_RULES_ENV_FILE); \
	fi
	$(SUDO) install -m 755 $(NFT_RULES_SCRIPT) $(NFT_RULES_INSTALL_PATH)
	$(SUDO) install -m 644 deploy/systemd/$(NFT_RULES_SERVICE) $(SYSTEMD_DIR)/$(NFT_RULES_SERVICE)
	$(SUDO) install -m 644 deploy/systemd/$(NFT_RULES_TIMER) $(SYSTEMD_DIR)/$(NFT_RULES_TIMER)
	$(SUDO) systemctl daemon-reload

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

deploy-nft-rules: install-nft-rules
	$(SUDO) systemctl start $(NFT_RULES_SERVICE)
	$(SUDO) systemctl enable --now $(NFT_RULES_TIMER)
