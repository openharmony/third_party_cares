#!/bin/bash
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation version 2.1
# of the License.
#
# Copyright(c) 2023 Huawei Device Co., Ltd.

SCRIPT_HOME=$(dirname $(readlink -f $0))

GEN_DIR="$1"
OPEN_EULER_CARES_SOURCE_PATH="c-ares-1.18.1"
SOURCE_PATH="$SCRIPT_HOME/$OPEN_EULER_CARES_SOURCE_PATH"
LOG_DIR="$GEN_DIR/openEulerCares"

mkdir -p "$GEN_DIR"
mkdir -p "$LOG_DIR"

init_logger() {
    LOG_FILE="$LOG_DIR/installOpenEurlCares.log"
    touch "$LOG_FILE"
}

write_log() {
    level="$1"
    message="$2"
    current_time=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$current_time | $level | OpenEulerCares | $message" >> "$LOG_FILE"
}

do_patch() {
    patch_path="$1"
    patch="$2"
    write_log "do_patch: cd $patch_path;patch -p1 < $patch"
    cd $patch_path;patch -p1 < $patch 2>&1 | while read -r line; do
        write_log "INFO" "do_patch result=[$line]"
    done
}

apply_patchs() {
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
  for patch_file in "${_all_patchs[@]}"
  do
    do_patch "$SOURCE_PATH" "$SCRIPT_HOME/$patch_file"
  done
}

install_cares() {
    tar_file_name="c-ares-1.18.1.tar.gz"
    tar_file="$SCRIPT_HOME/$tar_file_name"
    readme="README.OpenSource"
    cd "$SCRIPT_HOME" || exit

    if [ -d "$SOURCE_PATH" ]; then
        ctime=$(stat -c %Y "$SOURCE_PATH")
        nowtime=$(date +%s)
        difftime=$((nowtime - ctime))
        write_log "INFO" "nowTime=$nowtime, oldTime=$ctime"
        if [ $difftime -gt 300 ]; then
            write_log "INFO" "Removing OpenEuler Cares source path $SOURCE_PATH"
            rm -rf "$SOURCE_PATH"
            write_log "INFO" "Removed source path successfully"
        else
            write_log "INFO" "It's too new, does not need to remove OpenEuler Cares source path $source_path, diff time $difftime"
            return
        fi
    fi

    tar -xvf "$tar_file" -C "$SCRIPT_HOME" | while read -r line; do
        write_log "INFO" "tar result=[$line]"
    done
    if [ ! -d "$SOURCE_PATH" ]; then
        write_log "ERR" "Failed to unzip OpenEuler Cares tar $tar_file"
        return -1
    fi
}

main() {
    init_logger
    write_log "INFO" "start install c-ares script path is $SCRIPT_HOME."
    install_cares
    apply_patchs
    write_log "INFO" "c-ares install end."
}

main