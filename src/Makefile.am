ACLOCAL_AMFLAGS = -I m4
plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -I ${buildir}/src
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -lboost_regex -lsdbus-c++
arachne_la_SOURCES = \
        main.cpp \
        ArachnePlugin.cpp \
        ArachneLogger.cpp \
        ClientSession.cpp \
        Config.cpp \
        Http.cpp \
        Response.cpp \
        Request.cpp \
        Url.cpp

EXTRA_DIST= \
        ArachnePlugin.h \
        ArachneLogger.h \
        ClientSession.h \
        Config.h \
        FirewallD1.h \
        Http.h \
        Url.h

DBUS_GENERATED = FirewallD1_Proxy.h FirewallD1_Config_Proxy.h

clean-local:
	rm -f ${DBUS_GENERATED}
ArachnePlugin.cpp: ${DBUS_GENERATED}

FirewallD1_Proxy.h:
	dbus-send --system \
		--type=method_call \
		--dest=org.fedoraproject.FirewallD1 \
		--print-reply \
		/org/fedoraproject/FirewallD1 \
		org.freedesktop.DBus.Introspectable.Introspect \
	| sed -e '/^method return.*$$/d' -e 's/^\s* string\s*"//' -e 's/"$$//'\
	| xmlstarlet ed -L \
		-d '//node/interface[@name="org.freedesktop.DBus.Introspectable"]' \
		-d '//node/interface[@name="org.freedesktop.DBus.Properties"]' \
	| sdbus-c++-xml2cpp --proxy=$@

FirewallD1_Config_Proxy.h:
	dbus-send --system \
		--type=method_call \
		--dest=org.fedoraproject.FirewallD1 \
		--print-reply \
		/org/fedoraproject/FirewallD1/config \
		org.freedesktop.DBus.Introspectable.Introspect \
	| sed -e '/^method return.*$$/d' -e 's/^\s* string\s*"//' -e 's/"$$//' \
	| xmlstarlet ed -L \
		-d '//node/interface[@name="org.freedesktop.DBus.Introspectable"]' \
		-d '//node/interface[@name="org.freedesktop.DBus.Properties"]' \
	| sdbus-c++-xml2cpp --proxy=$@
