#!/bin/bash

. /etc/os-release
PLATFORM="${PLATFORM_ID/platform:/}"
if [ -z "$PLATFORM" ]; then
    PLATFORM="$ID"
fi
RPM_DIR="/build/repos/$PLATFORM"

echo "--- Prepare Environment ---"
mkdir -pv "$RPM_DIR"

for i in $ID_LIKE $ID ; do
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
    echo "--- Install rpmbuild ----"
    dnf install -y rpm-build which

    if [ "$ID" = "almalinux" ]; then
        echo "--- Install almalinux extras ---"
        dnf install -y 'dnf-command(config-manager)'
        dnf config-manager --set-enabled crb
        dnf install -y epel-release
    fi

    echo "--- Install Build Dependencies ---"
    dnf builddep -y /build/*spec
elif [ "$family" == "suse" ]; then
    zypper install -y rpm-build gawk
    zypper install -y $( rpmbuild -td *gz 2>&1 | awk '/is needed/ { print $1; }' )
elif [ "$family" == "debian" ]; then
    apt update
    apt install -y dh-make devscripts
fi

if [ -n "$( which rpm )" ]; then
    echo "--- Build RPM ---"
    rpmbuild -tb /build/*tar.gz --define "_rpmdir $RPM_DIR"
elif [ -n "$( which apt)" ]; then
    echo "Build DEB ---"
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

