ACLOCAL_AMFLAGS = -I m4

plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -g -std=c++11 -I/usr/include/dbus-1.0/ -I/usr/lib64/dbus-1.0/include
arachne_la_LDFLAGS = -module -avoid-version -shared
# arachne_la_LIBADD = -lboost_system -lboost_regex -ldbus-1
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
        Http.h \
        Url.h
