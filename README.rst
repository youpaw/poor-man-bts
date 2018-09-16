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

How to use it
-------------

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
   detected jump points with opcodes and information on where to get the
   destination from::

        $ head output.test
        # objname=objtool1
        0x74    0x00000000004019fe+0x00000002   0x0000000000401a05
        0xff    0x0000000000401a16+0x00000006   *0x21c5f4(32)
        0xff    0x0000000000401a20+0x00000006   *0x21c5f2(32)
        0xe9    0x0000000000401a2b+0x00000005   0x0000000000401a10
        0xff    0x0000000000401a30+0x00000006   *0x21c5ea(32)
        0xe9    0x0000000000401a3b+0x00000005   0x0000000000401a10
        0xff    0x0000000000401a40+0x00000006   *0x21c5e2(32)
        0xe9    0x0000000000401a4b+0x00000005   0x0000000000401a10
        0xff    0x0000000000401a50+0x00000006   *0x21c5da(32)
        0xe9    0x0000000000401a5b+0x00000005   0x0000000000401a10

#. Try it!::
  
        $ ./poormanbts output.test ./objtool1
        attached to 1 thread(s): 1884
        kpatch_ctl real cmdline="./objtool1\x00"
        Found 10 object file(s).
        objtool1: load offset: 0 = 400000 - 400000
        libz.so.1.2.8: load offset: 7f91ea3aa000 = 7f91ea3aa000 - 0
        libc-2.23.so: load offset: 7f91ea5c4000 = 7f91ea5c4000 - 0
        libelf-0.165.so: load offset: 7f91ea98e000 = 7f91ea98e000 - 0
        ld-2.23.so: load offset: 7f91eaba6000 = 7f91eaba6000 - 0
        Found 0 applied patch(es).
        objname = objtool1, load_addr = 0
        objname = libc-2.23.so, load_addr = 7f91ea5c4000
        from = 401cd0, to = 401cd6
        from = 401cdb, to = 401a50
        from = 401a56, to = 7f91eabbd870
        from = 7f91ea5e476a, to = 7f91ea5e4837
        from = 7f91ea5e4839, to = 7f91ea5e4779
        from = 7f91ea5e4785, to = 7f91ea5e4787
        from = 7f91ea5fe0b7, to = 7f91ea5fe0c5
        from = 7f91ea5fe0cc, to = 7f91ea5fe0e8
        ...


TODO
----

* Only print jump address via ``coverage``. Parse the rest from the executable
  via ``tools/objtool/arch/x86/decode``.
* Introduce single-stepping option. No need to execute any code on our own!
  Just restore original code and go on! (Merge this code with ``libcare``).
* Write a kernel module with ``kprobes``. Use ``post_handler`` to see where it
  all got to.
