#!/bin/sh

python -u signfast.py < sign.input

if [[ $TEST == 'slow' ]]; then
    python -u sign.py < sign.input
fi
