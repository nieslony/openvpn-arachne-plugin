ACLOCAL_AMFLAGS = -I m4
plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -I ${buildir}/src
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -lboost_regex -lsdbus-c++
arachne_la_SOURCES = \
        main.cpp \
        ArachneLogger.cpp \
        ArachnePlugin.cpp \
        ClientSession.cpp \
        Config.cpp \
        FirewallD1.cpp \
        Url.cpp

DBUS_GENERATED = FirewallD1_Proxy.h FirewallD1_Config_Proxy.h

EXTRA_DIST = ${DBUS_GENERATED} \
        ArachneLogger.h \
        ArachnePlugin.h \
        ClientSession.h \
        Config.h \
        FirewallD1.h \
        Http.h \
        Url.h

ArachnePlugin.cpp: ${DBUS_GENERATED}
main.cpp: ${DBUS_GENERATED}
