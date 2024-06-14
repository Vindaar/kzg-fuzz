#!/bin/sh

if ! (type nim > /dev/null); then
    msg="ERROR: Nim installation not found. Please install Nim, which \
is required to build Constantine's shared library. Read Constantine's \
README at
https://github.com/mratsim/constantine
and follow the instructions \
there to install Nim or head to
https://nim-lang.org"
    echo "$msg"
    exit 1
else
    echo "Nim installation found, continuing..."
fi

if [ ! -d constantine ]; then
    git clone https://github.com/mratsim/constantine
else
    echo "Constantine repository already exists, skipping clone."
fi

if [ ! -f constantine/lib/libconstantine.so ]; then
    cd constantine
    CC=clang nimble make_lib
else
    echo "Constantine library already built."
fi
