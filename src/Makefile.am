ACLOCAL_AMFLAGS = -I m4

plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -g -std=c++11 -I/usr/include/dbus-c++-1/
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -ldbus-c++-1
arachne_la_SOURCES =  FirewallD1.cpp FirewallD1_Config.cpp FirewallD1_Zone.cpp \
	Http.cpp Request.cpp Response.cpp Url.cpp \
	Logger.cpp \
	ArachnePlugin.cpp ClientSession.cpp \
	IniFile.cpp Firewall.cpp \
	main.cpp

EXTRA_DIST= \
	ArachnePlugin.h Url.h ClientSession.h IniFile.h \
	ArachnePlugin.h Url.h ClientSession.h FirewallD1.h \
	Http.h Logger.h \
	FirewallD1_Config.xml FirewallD1.xml \
	FirewallD1_proxy.h FirewallD1_Config_proxy.h

BUILT_SOURCES = FirewallD1_proxy.h \
	FirewallD1_Config_proxy.h

FirewallD1.xml:
	dbusxx-introspect --system \
		/org/fedoraproject/FirewallD1 \
		org.fedoraproject.FirewallD1 \
		> FirewallD1.xml

FirewallD1_Config.xml:
	dbusxx-introspect --system \
		/org/fedoraproject/FirewallD1/config \
		org.fedoraproject.FirewallD1 \
		> FirewallD1_Config.xml

FirewallD1_proxy.h: FirewallD1.xml
	dbusxx-xml2cpp $^ --proxy=$@

FirewallD1_Config_proxy.h: FirewallD1_Config.xml
	dbusxx-xml2cpp $^ --proxy=$@

clean-local:
	rm -fv $(BUILT_SOURCES) $(BUILT_SOURCES:_proxy.h=.xml)
