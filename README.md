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

run
======
to debug: 
    distccd --daemon --allow 10.10.10.0/24 d --verbose --no-detach --log-stderr -j8
deamon:
    distccd --daemon --allow 10.10.10.0/24 d -j8
