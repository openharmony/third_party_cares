#!/bin/bash
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation version 2.1
# of the License.
#
# Copyright(c) 2023 Huawei Device Co., Ltd.

SRC_DIR="$1"
CODE_DIR="$2"
OPEN_EULER_CARES_SOURCE_PATH="c-ares-1.18.1"
OPEN_EULER_CARES_TAR="c-ares-1.18.1.tar.gz"

set -e
if [ "$SRC_DIR" == "" ] || [ "$CODE_DIR" == "" ]; then
    exit 1
fi

if [ -d "$CODE_DIR" ]; then
    rm -rf "$CODE_DIR"
fi

mkdir -p $CODE_DIR

tar zxvf $SRC_DIR/$OPEN_EULER_CARES_TAR -C $CODE_DIR

_all_patchs=(
    "0000-Use-RPM-compiler-options.patch"
    "backport-disable-live-tests.patch"
    "backport-add-str-len-check-in-config_sortlist-to-avoid-stack-overflow.patch"
    "backport-CVE-2023-32067.patch"
    "backport-001-CVE-2023-31130.patch"
    "backport-002-CVE-2023-31130.patch"
    "backport-003-CVE-2023-31130.patch"
    "backport-001-CVE-2023-31147.patch"
    "backport-002-CVE-2023-31124_CVE-2023-31147.patch"
    "backport-003-CVE-2023-31147.patch"
    "backport-004-CVE-2023-31147.patch"
    "backport-005-CVE-2023-31147.patch"
    "backport-CVE-2023-31124.patch"
)
for filename in "${_all_patchs[@]}"
  do
    patch -d $CODE_DIR/$OPEN_EULER_CARES_SOURCE_PATH -p1 < $SRC_DIR/$filename --fuzz=0 --no-backup-if-mismatch
  done
exit 0