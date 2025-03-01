#!/usr/bin/python

# SPDX-FileCopyrightText: Copyright (c) 2018-2019 Virginia Tech
# SPDX-License-Identifier: Apache-2.0

import errno

cpuinfo = [dict(map(str.strip, line.split(":", 1))
                for line in block.splitlines())
           for block in open("/proc/cpuinfo", "r").read().split("\n\n")
           if len(block.strip())]

# Keep only primary hyperthreads
primaries = set()
for cpu in cpuinfo:
    processor = cpu["processor"]
    try:
        s = open("/sys/devices/system/cpu/cpu%s/topology/thread_siblings_list"
                 % processor).read()
    except EnvironmentError as e:
        if e.errno == errno.ENOENT:
            primaries.add(processor)
            continue
        raise
    try:
        ss = set(map(int, s.split("-")))
    except:
        ss = set(map(int, s.split(',')))
    if int(processor) == min(ss):
        primaries.add(processor)
cpuinfo = [cpu for cpu in cpuinfo if cpu["processor"] in primaries]


def seq(cpuinfo):
    packages = {}
    package_ids = set()
    for cpu in cpuinfo:
        if "physical id" in cpu:
            package_id = int(cpu["physical id"])
            packages.setdefault(package_id, []).append(cpu)
            if cpu["processor"] == "0":
                cpu0_package_id = int(package_id)
            package_ids.add(int(package_id))
        else:
            yield cpu
    for cpu in packages[cpu0_package_id]:
        yield cpu
    package_ids.remove(cpu0_package_id)

    for package_id in package_ids:
        for cpu in packages[package_id]:
            yield cpu


def order():
    for cpu in seq(cpuinfo):
        yield cpu["processor"]


if __name__ == "__main__":
    with open("cpuseq.h", "w") as f:
        f.write("int online_cpus = %d;\n" % (sum(1 for x in order())))
        f.write("int cpuseq[] = { %s " % ", ".join(order()) + "};\n")
