#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2023 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import fcntl
import os
import shutil
import sys
import time
import traceback

class CaresLog:
    IS_DEBUG = False
    _f = None

    @staticmethod
    def init_logger(log_path):
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        CaresLog._f = open(os.path.join(log_path, "installOpenEurlCares.log"), "w")
        pass

    @staticmethod
    def close():
        if CaresLog._f is None:
            return;
        CaresLog._f.close()

    @staticmethod
    def __get_current_time():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    @staticmethod
    def info(info):
        content = "%s | INFO | OpenEulerCares | %s" % (CaresLog.__get_current_time(), info)
        CaresLog._f.write("%s\n" % (content))
        if CaresLog.IS_DEBUG:
            print(content)
        pass

    @staticmethod
    def warn(error):
        content = "%s | WARN | OpenEulerCares | %s" % (CaresLog.__get_current_time(), error)
        CaresLog._f.write("%s\n" % (content))
        print(content)
        pass

    @staticmethod
    def error(error):
        content = "%s | ERR  | OpenEulerCares | %s" % (CaresLog.__get_current_time(), error)
        CaresLog._f.write("%s\n" % (content))
        print(content)
        pass

    @staticmethod
    def exception(error):
        stack = traceback.format_exc()
        content = "%s | ERR  | OpenEulerCares | %s" % (CaresLog.__get_current_time(), stack)
        CaresLog._f.write("%s\n" % (content))
        print(content)
        pass


class Patch:
    _patch_path = None
    _source_path = None
    _all_patchs = [
        "0000-Use-RPM-compiler-options.patch",
        "backport-disable-live-tests.patch",
        "backport-add-str-len-check-in-config_sortlist-to-avoid-stack-overflow.patch",
        "backport-CVE-2023-32067.patch",
        "backport-001-CVE-2023-31130.patch",
        "backport-002-CVE-2023-31130.patch",
        "backport-003-CVE-2023-31130.patch",
        "backport-001-CVE-2023-31147.patch",
        "backport-002-CVE-2023-31124_CVE-2023-31147.patch",
        "backport-003-CVE-2023-31147.patch",
        "backport-004-CVE-2023-31147.patch",
        "backport-005-CVE-2023-31147.patch",
        "backport-CVE-2023-31124.patch"
    ]

    _my_patchs = [
    ]

    @staticmethod
    def init(patch_path, source_path):
        Patch._patch_path = patch_path
        Patch._source_path = source_path
        pass

    @staticmethod
    def _is_success(messages):
        if len(messages) <= 0:
            return False

        err_code = messages[len(messages) - 1].rstrip()
        if err_code == "0":
            return True
        else:
            return False

    @staticmethod
    def _do_patch(patch_path, patch):
        patch_file = os.path.join(patch_path, patch)
        if os.path.exists(patch_file):
            cmd = "cd %s; patch -p1 < %s 2>&1; echo $?;" % (Patch._source_path, patch_file)
            messages = os.popen(cmd).readlines()
            if len(messages) == 0:
                CaresLog.info("%s patch result empty" % (patch_file))

            isSuccess = Patch._is_success(messages)
            if isSuccess is False:
                CaresLog.error("patch error %s" % (patch_file))
            for message in messages:
                if isSuccess:
                    CaresLog.info("patch result [%s]" % (message.rstrip()))
                else:
                    CaresLog.error("patch result [%s]" % (message.rstrip()))
        else:
            CaresLog.error("patch does not exits %s" % (patch_file))
        pass

    @staticmethod
    def patch_all():
        count = 0
        for patch in Patch._all_patchs:
            count = count + 1
            CaresLog.info("the OpenEuler Cares's %d patch %s" % (count, patch))
            Patch._do_patch(Patch._patch_path, patch)
            pass

        my_pathch_path = os.path.join(Patch._patch_path, "customized", "patch")
        for patch in Patch._my_patchs:
            count = count + 1
            CaresLog.info("my OpenEuler Cares's %d patch %s" % (count, patch))
            Patch._do_patch(my_pathch_path, patch)
        pass


class Installer:
    _tar_file_name = "c-ares-1.18.1.tar.gz"
    _open_euler_cares_source_path = "c-ares-1.18.1"
    _read_me = "README.OpenSource"

    def __init__(self, script_home):
        self.script_home = script_home
        Patch.init(self.script_home, os.path.join(self.script_home, Installer._open_euler_cares_source_path))
        pass

    def __unzip_open_cares_tar(self):
        tar_file = os.path.join(self.script_home, Installer._tar_file_name)
        source_path = os.path.join(self.script_home, Installer._open_euler_cares_source_path)
        try:
            if os.path.exists(source_path):
                cTime = os.path.getctime(source_path)
                nowTime = time.time()
                diffTime = int(abs(nowTime - cTime))
                CaresLog.info("nowTime=%d, oldTime=%d" % (nowTime, cTime))
                if diffTime > 300: # create the directory is too old
                    CaresLog.info("remove OpenEuler Cares source path %s" % (source_path))
                    shutil.rmtree(source_path)
                    CaresLog.info("remove source path successful")
                else:
                    CaresLog.info("it's too new, does not need to remove OpenEuler Cares source path %s, diff time %d"
                                    % (source_path, diffTime))
                    return 1

            messages = os.popen("cd %s; tar -xvf %s 2>&1" % (self.script_home, Installer._tar_file_name)).readlines()
            for message in messages:
                CaresLog.info("tar result=[%s]" % (message.rstrip()));

            if os.path.exists(source_path) is False:
                CaresLog.error("can not unzip OpenEuler Cares tar %s" % (tar_file))
                return -1

            CaresLog.info("unzip OpenEuler Cares tar successful %s" % (tar_file))

            # srcIncludePath = os.path.join(source_path, "include")
            # destIncludePath = os.path.join(self.script_home, "include")

            # if os.path.exists(destIncludePath):
            #     shutil.rmtree(destIncludePath)
            #     CaresLog.info("remove include path successful")
            #     pass

            # CaresLog.info("copy include from %s to %s" % (srcIncludePath, destIncludePath))
            # result = shutil.copytree(srcIncludePath, destIncludePath)
            # CaresLog.info("copy result [%s]" % (result))

            return 0
        except Exception as e:
            CaresLog.error("can not unzip OpenEuler Cares tar %s" % (tar_file))
            CaresLog.exception(e)
            return -1

    def __init_repo(self):
        return self.__unzip_open_cares_tar()

    def __install(self):
        CaresLog.info("create OpenEuler Cares repo")
        ret = self.__init_repo()
        if ret == 1:
            CaresLog.warn("reuse the soruce path %s" % (Installer._open_euler_cares_source_path))
            return
        elif ret == -1:
            CaresLog.error("create OpenEuler Cares repo failed")
            return

        CaresLog.info("patch OpenEuler Cares")
        Patch.patch_all()
        CaresLog.warn("OpenEuler Cares has been install")
        pass

    def install(self):
        read_me_file = os.path.join(self.script_home, Installer._read_me)
        with open(read_me_file, "r") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            CaresLog.warn("only me to install OpenEuler Cares")
            self.__install()
            fcntl.flock(f, fcntl.LOCK_UN)
        pass


def main():
    script_home = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser()
    parser.add_argument('--gen-dir', help='generate path of log', required=True)
    args = parser.parse_args()

    CaresLog.init_logger(os.path.join(args.gen_dir, "openEulerCares"))
    CaresLog.warn("script path is %s, log path is %s" % (script_home, args.gen_dir))
    installer = Installer(script_home)
    installer.install()
    CaresLog.warn(os.path.exists("/root/ohos231107/ohos_trunk/third_party/cares/include/ares_config.h"))
    CaresLog.warn(os.path.exists("/root/ohos231107/ohos_trunk/third_party/cares/include/ares.h"))
    CaresLog.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
    
