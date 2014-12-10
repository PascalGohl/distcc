distcc
======

patched distcc 3.2rc1 with -march=native support

install
======
    export CXXFLAGS="-Wno-error"
    export CFLAGS="-Wno-error"
    ./configure
    make -j8
    sudo make install
