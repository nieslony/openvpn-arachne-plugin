#!/bin/bash

ZBUS_XMLGEN_BIN="$HOME/.cargo/bin/zbus-xmlgen"
DEST_DIR=src/firewalld

if [ ! -e "$ZBUS_XMLGEN_BIN" ]; then
    cargo install zbus_xmlgen
fi

mkdir -pv "$DEST_DIR"

(
    cd "$DEST_DIR"
    sudo ~/.cargo/bin/zbus-xmlgen system org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1
    sudo ~/.cargo/bin/zbus-xmlgen system org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1/config
)
