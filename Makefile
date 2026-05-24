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
CUSTOM_POLICY := internal/config/custom_local.go
CUSTOM_POLICY_EXAMPLE := examples/custom_local.go.example
SUDO ?= sudo

.PHONY: build install install-systemd setup-user configure-custom deploy

build:
	go build -o $(BUILD_OUTPUT) $(BUILD_TARGET)

install: build
	$(SUDO) install -m 755 $(BUILD_OUTPUT) $(TMP_INSTALL_PATH)
	$(SUDO) mv -f $(TMP_INSTALL_PATH) $(INSTALL_PATH)

install-systemd:
	$(SUDO) install -m 644 deploy/systemd/picosrv.service $(SYSTEMD_DIR)/picosrv.service
	$(SUDO) install -m 644 deploy/systemd/picosrv.socket $(SYSTEMD_DIR)/picosrv.socket
	$(SUDO) systemctl daemon-reload

setup-user:
	if ! getent group $(SERVICE_GROUP) >/dev/null; then \
		$(SUDO) groupadd --system $(SERVICE_GROUP); \
	fi
	if ! getent passwd $(SERVICE_USER) >/dev/null; then \
		$(SUDO) useradd --system --gid $(SERVICE_GROUP) --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER); \
	fi

configure-custom:
	if [ ! -f $(CUSTOM_POLICY) ]; then \
		cp $(CUSTOM_POLICY_EXAMPLE) $(CUSTOM_POLICY); \
	fi
	EDITOR="$${EDITOR:-vim}" sh -c '"$$EDITOR" "$(CUSTOM_POLICY)"'

deploy: setup-user build install install-systemd
