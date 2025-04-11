#!/bin/bash -ex

make defconfig
echo "CONFIG_DEBUG_SERIAL=y" >> .config
echo "CONFIG_DEBUG_SERIAL_PORT=0x3f8" >> .config
sed -i 's/CONFIG_RELOCATE_INIT=y/# CONFIG_RELOCATE_INIT is not set/' .config
