#!/bin/bash

function get_git_version {
    cur_version=$(
        cat configure.ac \
            | grep AC_INIT \
            | grep -Eo '\[[^]]+\]' \
            | head -2 \
            | tail -1 \
            | grep -o '\[[0-9.]*[0-9]' \
            | tr -d '['
    )
    echo -n "$cur_version.git_$(date +%y%m%d%H%M)_$(git rev-parse --short HEAD)"
}

if [ -z "$1" ]; then
    VERSION="$( get_git_version )"
else
    VERSION="$1"
fi

TEMP_FILE=$(mktemp)

cat configure.ac | awk -v version="$VERSION" '
    /^AC_INIT/ {
        gsub(/\[[0-9][^]]*\]/, "[" version "]");
        print $0;
        next;
    }
    { print $0; }
' > $TEMP_FILE

mv -v $TEMP_FILE configure.ac
