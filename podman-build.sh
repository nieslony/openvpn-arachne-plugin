#!/bin/bash

. /etc/os-release
SRC_DIR=$( dirname $0 )

if [ -z "$1" ]; then
    BUILD_DISTRO="$ID:$VERSION_ID"
else
    BUILD_DISTRO="$1"
fi

if netstat -tln | grep 3128 -q ; then
    my_ip="$( host $HOSTNAME | awk '{ print $NF; }' | head -1 )"
    HTTP_PROXY=http://$my_ip:3128
fi


echo "=== Build for disto $BUILD_DISTRO ==="
HTTP_PROXY=$HTTP_PROXY http_proxy=$HTTP_PROXY \
    podman run \
        -ti \
        --rm \
        --workdir=/build \
        --volume $SRC_DIR:/build:Z \
        --network=host \
        --http-proxy \
        $BUILD_DISTRO \
        ./build.sh

