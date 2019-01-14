ACLOCAL_AMFLAGS = -I m4

plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -g -std=c++11 -I/usr/include/dbus-1.0/ -I/usr/lib64/dbus-1.0/include
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -ldbus-1
arachne_la_SOURCES = \
	Http.cpp Request.cpp Response.cpp Url.cpp \
	Logger.cpp \
	ArachnePlugin.cpp ClientSession.cpp \
	IniFile.cpp Firewall.cpp \
	main.cpp

EXTRA_DIST= \
	ArachnePlugin.h  ClientSession.h  Firewall.h  Http.h  IniFile.h  Logger.h  Url.h

clean-local:
	rm -fv $(BUILT_SOURCES) $(BUILT_SOURCES:_proxy.h=.xml)
