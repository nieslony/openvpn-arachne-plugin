#!/bin/bash

set -eu

. /etc/os-release

if [ -z "${PLATFORM_ID+x}" ]; then
    PLATFORM=$ID:$VERSION_ID
else
    PLATFORM=${PLATFORM_ID/platform:/}
fi

RPM_DIR="/repos/$PLATFORM"

function log {
    echo "--- $@ ---"
}

function create_tar {
    mkdir -p /build-tar
    dnf install -y rsync
    rm -rf /build-tar
    rsync -av /source/ /build-tar
    pushd /build-tar

    log "Spec file is missing, try to generate from .spec.in"
    VERSION_INFO=$(
        cat configure.ac \
            | grep "^AC_INIT" \
            | grep -o '\[[a-z0-9.\-]*\]' \
            | tr -d '[]' \
            | tr '\n' ' '
    )
    PROG_NAME=$( echo $VERSION_INFO | cut -d ' ' -f1 )
    PROG_VERSION=$( echo $VERSION_INFO | cut -d ' ' -f2 )
    cat *spec.in \
        | sed -E "s/@PACKAGE_NAME@/$PROG_NAME/ ; s/@PACKAGE_VERSION@/$PROG_VERSION/" \
        > $PROG_NAME.spec
    popd
}

log "Prepare Environment"
mkdir -pv "$RPM_DIR"

for i in ${ID_LIKE:-} ${ID:-} ; do
    case $i in
        rhel|fedora)
            family=rhel
            break
            ;;
        suse)
            family=suse
            break
            ;;
        debian)
            family=debian
            break
            ;;
    esac
done
if [ -z "$family" ]; then
    echo Unkwnoen OS family.
    exit 1
fi

if [ "$family" == "rhel" ]; then
    if grep -q "^proxy=" /etc/dnf/dnf.conf ; then
        sed -i "s#^proxy=.*#proxy=${http_proxy}#" /etc/dnf/dnf.conf
    else
        echo "proxy=${http_proxy}" >> /etc/dnf/dnf.conf
    fi

    if [ "$ID" = "almalinux" ]; then
        echo "--- Install almalinux extras ---"
        dnf install -y 'dnf-command(config-manager)'
        dnf config-manager --set-enabled crb
        dnf install -y epel-release
    fi

    log "Install rpmbuild"
    dnf install -y rpm-build which createrepo

    SPEC_FILE="$( ls *spec 2> /dev/null ; true )"
    SPEC_IN_FILE="$( ls *spec.in 2> /dev/null ; true )"
    if [ -z "$SPEC_FILE" -a -n "$SPEC_IN_FILE" ]; then
        create_tar
    fi

    log "Install Build Dependencies"
    dnf builddep -y /build-tar/*spec

    TAR_FILE="$( ls *.tar.* ; true )"
    if [ -z "$TAR_FILE" ]; then
        pushd /build-tar
        log "Tar file does not exist, running 'make dist'"
        dnf install -y automake libtool autoconf-archive
        ./gen-auto.sh
        ./configure
        make dist
        popd
    fi
elif [ "$family" == "suse" ]; then
    zypper install -y rpm-build gawk
    zypper install -y $( rpmbuild -td *gz 2>&1 | awk '/is needed/ { print $1; }' )
elif [ "$family" == "debian" ]; then
    apt update
    apt install -y dh-make devscripts
fi

TAR_FILE=$( ls -1 /source/*tar.gz /build-tar/*tar.gz 2>/dev/null | head -1 ; true )

if [ -n "$( which rpm )" ]; then
    log "Build RPM"
    rpmbuild -tb $TAR_FILE --define "_rpmdir $RPM_DIR"
    createrepo $RPM_DIR
elif [ -n "$( which apt)" ]; then
    log "Build DEB"
    mkdir ~/DEBIAN
    cat *spec | awk '
        /^Name:/    { print "Package:     " $2; }
        /^Version:/ { print "Version:     " $2; }
        /^Summary:/ { print "Description: " $2; }
        END {
            print "Architecture: all";
            print "Maintainer: King Foo"
        }
        ' | tee ~/DEBIAN/control
fi
