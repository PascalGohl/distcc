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

configure server on compile PC
======
    sudo sh -c 'echo "10.10.10.0/24" >> /usr/local/etc/distcc/clients.allow'

run server in debug mode
======
the distcc server starts by default, therefore you have to kill it with

   killall distcc
   
run to debug: 

    distccd --daemon --allow 10.10.10.0/24 d --verbose --no-detach --log-stderr -j8
    
deamon:

    distccd --daemon --allow 10.10.10.0/24 d -j8
