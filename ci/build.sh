#! /usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
. ${SCRIPT_DIR}/common.sh

set -e
set -x

if [[ "${ZEEK_CI_RUNNER_OS}" == "darwin" ]]; then
    # Starting with Monterey & Xcode 13.1 we need to help it find OpenSSL
    if [ -d /usr/local/opt/openssl@1.1/lib/pkgconfig ]; then
        export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/opt/openssl@1.1/lib/pkgconfig
    fi
fi

if [[ "${ZEEK_CI_CREATE_ARTIFACT}" != "1" ]]; then
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} ${ZEEK_CI_CONFIGURE_FLAGS_EXTRA}
    cd build
    make -j ${ZEEK_CI_CPUS}
else
    ./configure ${ZEEK_CI_CONFIGURE_FLAGS} ${ZEEK_CI_CONFIGURE_FLAGS_EXTRA} --prefix=${CIRCLE_WORKING_DIRECTORY}/${CIRCLE_PROJECT_REPONAME}/install
    cd build
    make -j ${ZEEK_CI_CPUS} install
    cd ..
    tar -czf ${CIRCLE_WORKING_DIRECTORY}/${CIRCLE_PROJECT_REPONAME}/build.tgz ${CIRCLE_WORKING_DIRECTORY}/${CIRCLE_PROJECT_REPONAME}/install
fi
