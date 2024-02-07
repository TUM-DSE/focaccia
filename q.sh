#!/bin/sh


if [ ! -f qemu.trace ]; then
    cp tools/* .
    ./capture_transforms.py -o qemu.sym ../hello-static-musl
    ./verify_qemu.py 1234 --symb-trace qemu.sym -o qemu.trace --quiet --gdb /nix/store/2sqfafwfb3zg71qhak846xphmcdndzq0-gdb-14.1/bin/gdb &
    qemu-x86_64 -g 1234 ../hello-static-musl &> /dev/null

    rm qemu.sym verify_qemu.py convert.py capture_transforms.py _qemu_tool.py
fi


./focaccia.py --error-level info --symbolic -p ../hello-static-musl -t qemu.trace -r
