ACLOCAL_AMFLAGS = -I m4
plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -I ${buildir}/src
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -lboost_regex -lboost_iostreams -lsdbus-c++
arachne_la_SOURCES = \
        main.cpp \
        ArachneLogger.cpp \
        ArachnePlugin.cpp \
        ClientSession.cpp \
        Config.cpp \
        BreakDownRootDaemon.cpp \
        FirewallD1.cpp \
        Url.cpp

DBUS_GENERATED_1 = firewalld-proxy-sdbus-1/FirewallD1_Config_IpSet_Proxy.h \
	firewalld-proxy-sdbus-1/FirewallD1_Config_Policy_Proxy.h \
	firewalld-proxy-sdbus-1/FirewallD1_Config_Proxy.h \
	firewalld-proxy-sdbus-1/FirewallD1_Proxy.h
DBUS_GENERATED_2 = firewalld-proxy-sdbus-2/FirewallD1_Config_IpSet_Proxy.h \
	firewalld-proxy-sdbus-2/FirewallD1_Config_Policy_Proxy.h \
	firewalld-proxy-sdbus-2/FirewallD1_Config_Proxy.h \
	firewalld-proxy-sdbus-2/FirewallD1_Proxy.h


if SDBUS_CPP_1
DBUS_GENERATED = ${DBUS_GENERATED_1}
endif
if SDBUS_CPP_2
DBUS_GENERATED = ${DBUS_GENERATED_2}
endif

EXTRA_DIST = ${DBUS_GENERATED_1} ${DBUS_GENERATED_2} \
	ArachneLogger.h \
        ArachnePlugin.h \
        ClientSession.h \
        Config.h \
        BreakDownRootDaemon.h \
        FirewallD1.h \
        Http.h \
        Url.h

dummy:
	echo ${DBUS_GENERATED}

ArachnePlugin.cpp: ${DBUS_GENERATED}
main.cpp: ${DBUS_GENERATED}
