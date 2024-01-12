#!/bin/bash


declare -A dbus_proxies=(
    ["FirewallD1_Config_Proxy.h"]="/org/fedoraproject/FirewallD1/config"
    ["FirewallD1_Proxy.h"]="/org/fedoraproject/FirewallD1"
)

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
 	| sdbus-c++-xml2cpp --proxy=$header
done



