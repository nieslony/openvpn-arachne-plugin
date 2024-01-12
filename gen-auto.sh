#!/bin/bash

echo --- Removing old files... ---
rm -rvf .gen-auto.sh.kate-swp \
        Makefile.in \
        aclocal.m4 \
        ar-lib \
        autom4te.cache/ \
        compile \
        config.guess \
        config.sub \
        configure \
        depcomp \
        install-sh \
        ltmain.sh \
        m4/ \
        missing \
        src/Makefile.in \


if [ "$1" = "clean" ]; then
    exit
fi

echo --- libtoolize ---
libtoolize --copy || exit 1

echo --- aclocal ---
aclocal || exit 1

echo ---autoconf ---
autoconf || exit 1

echo --- automake ---
automake --add-missing --copy || exit 1
