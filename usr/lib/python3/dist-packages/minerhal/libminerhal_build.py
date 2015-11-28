import os.path
import subprocess
import cffi
import re

ffi = cffi.FFI()

################################################################################

PROJECT_DIR = subprocess.Popen("git rev-parse --show-toplevel", shell=True, stdout=subprocess.PIPE).stdout.read().strip().decode()
SRC_DIR = PROJECT_DIR + "/src"
BUILD_DIR = PROJECT_DIR + "/build"

if not os.path.exists(BUILD_DIR + "/libminerhal.a"):
    subprocess.call(["make", "-C", PROJECT_DIR, "lib"])

################################################################################


header_files = [
    SRC_DIR + "/version.h",
    SRC_DIR + "/io/time.h",
    SRC_DIR + "/io/i2c.h",
    SRC_DIR + "/io/pmbus.h",
    SRC_DIR + "/io/spi.h",
    SRC_DIR + "/io/pmbus_cmds.h",
    SRC_DIR + "/io/pin.h",
    SRC_DIR + "/platform/linux/linux_spi.h",
    SRC_DIR + "/platform/linux/linux_i2c.h",
    SRC_DIR + "/platform/linux/linux_pin.h",
    SRC_DIR + "/platform/linux/linux_pmbus.h",
    SRC_DIR + "/drivers/mcp23008/mcp23008.h",
    SRC_DIR + "/drivers/si5351/si5351.h",
    SRC_DIR + "/drivers/eescs21/eescs21_params.h",
    SRC_DIR + "/drivers/eescs21/eescs21.h",
    SRC_DIR + "/drivers/pv3012/pv3012.h",
    SRC_DIR + "/drivers/pv3012/pv3012_cmds.h",
    SRC_DIR + "/drivers/pac1710/pac1710.h",
    SRC_DIR + "/miners/miner.h",
    SRC_DIR + "/miners/rpi2miner/rpi2miner.h",
    SRC_DIR + "/miners/cpuminer/cpuminer.h",
]

################################################################################


# Dump a file
def dump(filename):
    with open(filename) as f:
        return f.read()

# Filter out #include directives
include_pattern = re.compile(r"#include\s*.*[\n]*")
def filter_include(data):
    return include_pattern.sub("\n", data)

# Filter out include preprocessor guards
include_guard_pattern = re.compile(r"#ifndef\s*([a-zA-Z0-9_]*)\n#define \1\n(.*)#endif[\n]*", flags=re.DOTALL)
def filter_include_guard(data):
    return include_guard_pattern.sub(r"\2", data)

# Substitute #define values with "..."
defines_table = {}
define_pattern = re.compile(r"#define\s*([a-zA-Z0-9_]*)\s*(\S*)\n")
def filter_transform_defines(data):
    for (define, value) in define_pattern.findall(data):
        if define in defines_table:
            # Delete duplicate defines
            data = re.sub(r"#define\s*" + define + r"\s*\S*\n", r"\n", data)
        else:
            # Track define value
            defines_table[define] = value
    return define_pattern.sub(r"#define \1 ...\n", data)

# Substitute array constants with their values
def filter_transform_constants(data):
    for define in defines_table:
        data = re.sub(r"\[{}\]".format(define), "[{}]".format(defines_table[define]), data)
    return data

header_to_def_pipeline = [dump, filter_include, filter_include_guard, filter_transform_defines, filter_transform_constants]

################################################################################

# ffi.set_source()
ffi.set_source("minerhal.libminerhal", "\n".join([dump(filename) for filename in header_files]),
               include_dirs=[SRC_DIR, SRC_DIR + "/drivers/eescs21"],
               extra_objects=[BUILD_DIR + "/libminerhal.a"],
               libraries=["rt", "crypto", "pthread"])

# ffi.cdef()
ffi.cdef("typedef _Bool bool;") # <stdbool.h>
for filename in header_files:
    data = filename
    for func in header_to_def_pipeline:
        data = func(data)
    ffi.cdef(data)

if __name__ == "__main__":
    ffi.compile()

