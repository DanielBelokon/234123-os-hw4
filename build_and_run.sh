#!/bin/bash

TESTS_GLOB=$1

mkdir -p build
cd build

cmake .. && make
if [ $? -eq 0 ]; then
    sudo sysctl -w vm.nr_hugepages=102400
    cd tests
    if [ -z "$TESTS_GLOB" ]; then
        ctest --output-on-failure
    else
        ctest -R "$TESTS_GLOB" --output-on-failure
    fi
fi
