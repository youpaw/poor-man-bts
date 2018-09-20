Poor Man's BTS
==============

Do you feel sad how all your older friend have Branch Trace Storage and other
fancy things to aid branch debugging? Or are you trying to trace branches
inside a VM for the program that you don't have source code for or unwilling to
compile with ``gprof`` support?

Here you go! A Branch Trace Storage for the poor! Welcome aboard! Next stop is
kernel module for the BTS-like reports!

Please note that this is still some alpha-level software. Pull requests are
welcome!

Userspace: How to use it
------------------------

#. Clone it and init submodules::

        git clone https://github.com/paboldin/poor-man-bts
        cd poor-man-bts
        git submodule init && git submodule update

#. Build it via make::

        $ make

#. Use ``objtool coverage`` to get a list of jump points for an executable::

	$ ./objtool coverage objtool > output.test

#. And even for a library it may load!::

        $ ./objtool coverage /lib/x86_64-linux-gnu/libc-2.23.so >> output.test

#. Take a look at what is in ``output.test`` file. It contains a list of
   detected jump points. Opcodes and destination information are parsed
   from the running application memory::

        $ head output.test
        # objname=objtool
        0x401a6e+0x2
        0x401a70+0x5
        0x401a86+0x6
        0x401a90+0x6
        0x401a9b+0x5
        0x401aa0+0x6
        ...

#. Try it!::
  
        $ ./poormanbts output.test ./objtool
        attached to 1 thread(s): 9107
        kpatch_ctl real cmdline="./objtool\x00"
        Found 10 object file(s).
        objtool: load offset: 0 = 400000 - 400000
        libz.so.1.2.8: load offset: 7f09ee75f000 = 7f09ee75f000 - 0
        libc-2.23.so: load offset: 7f09ee979000 = 7f09ee979000 - 0
        libelf-0.165.so: load offset: 7f09eed43000 = 7f09eed43000 - 0
        ld-2.23.so: load offset: 7f09eef5b000 = 7f09eef5b000 - 0
        Found 0 applied patch(es).
        objname = objtool, load_addr = 0
        call from = 4023e4, to = 401d10
        jmp from = 401d10, to = 401d16
        jmp from = 401d1b, to = 401a80
        jmp from = 401a86, to = 7f09eef72870
        call from = 41392c, to = 401a60
        jmp from = 401a6e, to = 401a75
        jmp from = 413934, to = 413936
        call from = 413949, to = 402490
        jmp from = 402499, to = 40249b
        ...

Kernel module: how to use it
----------------------------

Kernel module is even more magical! Since Linux kernel provides means to
resolve symbol name into a address and size we will use these to find
branches there!


#. First, build the module::

        $ cd kmod
        $ make
        ...

   You should have linux headers installed.

#. Next, insert the module::

        $ sudo insmod ./poormanbts.ko

#. Finally, add a trace point::

        $ echo strlen | sudo tee /proc/poormanbts

#. Enjoy the results::

        $ sudo cat /proc/poormanbts

TODO
----

* Introduce single-stepping option. No need to execute any code on our own!
  Just restore original code and go on! (Merge this code with ``libcare``).
