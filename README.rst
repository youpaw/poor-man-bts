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
        git submodule init
        git submodule update libcare
        git submodule update linux-objtool-coverage --depth 1

   I have to use submodule for ``linux-objtool-coverage``. If you know how to
   move ``tools/objtool`` away from the kernel let me know!

#. Build it via make::

        $ make

#. Use ``objtool coverage`` to get a list of jump points for an executable::

	$ cp linux-objtool-coverage/tools/objtool objtool1
	$ linux-objtool-coverage/tools/objtool coverage --no-kpatch objtool1 > output.test

#. Take a look at what is in ``output.test`` file. It contains a list of
   detected jump points with opcodes and information on where to get the
   destination from::

        $ head output.test
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

#. Use ``./poormanbts output.test objtool1`` to generate
   branching report for the code.
