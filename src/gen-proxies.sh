#!/bin/bash

declare -A dbus_proxies=(
    ["FirewallD1_Config_IpSet_Proxy.h"]="/org/fedoraproject/FirewallD1/config/ipset/0"
    ["FirewallD1_Config_Policy_Proxy.h"]="/org/fedoraproject/FirewallD1/config/policy/0"
    ["FirewallD1_Config_Proxy.h"]="/org/fedoraproject/FirewallD1/config"
    ["FirewallD1_Proxy.h"]="/org/fedoraproject/FirewallD1"
)

if [ -e /usr/lib64/libsdbus-c++.so.2 ]; then
	SDBUS_VERSION=2
elif [ -e /usr/lib64/libsdbus-c++.so.1 ]; then
	SDBUS_VERSION=1
else
	echo "Cannot detect sdbus version."
	exit 1
fi

echo Found sdbus-c++ version $SDBUS_VERSION
OUT_DIR=firewalld-proxy-sdbus-$SDBUS_VERSION
mkdir -v $OUT_DIR

for header in "${!dbus_proxies[@]}" ; do
    echo "--- Creating $header from ${dbus_proxies[$header]} ---"

    dbus-send --system \
		--type=method_call \
		--dest=org.fedoraproject.FirewallD1 \
		--print-reply \
		${dbus_proxies[$header]} \
		org.freedesktop.DBus.Introspectable.Introspect \
 	| sed -e '/^method return.*$/d' -e 's/^\s* string\s*"//' -e 's/"$//' \
  	| xmlstarlet ed -L \
  		-d '//node/interface[@name="org.freedesktop.DBus.Introspectable"]' \
  		-d '//node/interface[@name="org.freedesktop.DBus.Properties"]' \
 	| sdbus-c++-xml2cpp --proxy=$OUT_DIR/$header
done
