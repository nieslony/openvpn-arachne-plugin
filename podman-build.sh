#!/bin/bash

set -eu

. /etc/os-release
SRC_DIR=$( dirname $0 )

REPO_DIR=$PWD/repos
if [ ! -e "$REPO_DIR" ]; then
    mkdir -v $REPO_DIR
fi

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
        --workdir=/source \
        --volume $SRC_DIR:/source:ro,Z \
        --volume $REPO_DIR:/repos:Z \
        --network=host \
        --http-proxy \
        --env HTTP_PROXY=$HTTP_PROXY \
        --env http_proxy=$HTTP_PROXY \
        $BUILD_DISTRO \
        ./build.sh
