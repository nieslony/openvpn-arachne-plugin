#!/bin/bash

echo --- Removing old files... ---
find -maxdepth 1 -type l -delete -print

rm -rfv aclocal.m4 autom4te.cache m4 configure  Makefile.in config.status  
rm -rfv Makefile  config.h  stamp-h1  libtool  config.log build plugins

if [ "$1" = "clean" ]; then
    exit
fi

echo --- libtoolize ---
libtoolize

echo --- aclocal ---
aclocal 

echo ---autoconf ---
autoconf

echo --- automake ---
automake --add-missing
