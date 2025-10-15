# This is a Yocto recipe file. 

DESCRIPTION = "A beginner-friendly kernel module to set hardware watchpoints"

LICENSE = "GPL-2.0-only"

LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

# 'inherit module' tells BitBake to use its built-in rules for compiling kernel modules. It knows how to find the kernel source, how to call the compiler, and where to put the final .ko file. It saves us from writing a Makefile!

inherit module
# This tells BitBake where to find our source code.
# "file://" means look in the same directory as this recipe file.

SRC_URI = "file://watchpoint-mod.c\
           file://Makefile \
           "

# By setting S to ${UNPACKDIR}, we're telling it the .c file is at the top level of that directory.

S = "${UNPACKDIR}"

# Override do_install bc error accure.
do_install() {
    # Create the destination directory
    install -d ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra

    # Find and install any .ko file built in the source tree
    find ${S} -name "*.ko" -exec install -m 0644 {} ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra/ \;
}