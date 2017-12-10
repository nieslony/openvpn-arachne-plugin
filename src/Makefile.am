ACLOCAL_AMFLAGS = -I m4

plugin_LTLIBRARIES = arachne.la
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system
arachne_la_SOURCES = \
	main.cpp ArachnePlugin.cpp Url.cpp ClientSession.cpp

EXTRA_DIST= \
	ArachnePlugin.h Url.h ClientSession.h


