Poor Man's BTS
==============

Do you feel sad how all your older friend have Branch Trace Storage and other
fancy things to aid branch debugging? Or are you trying to trace branches
inside a VM for the program that you don't have source code for or unwilling to
compile with ``gprof`` support?

Here you go! A Branch Trace Storage for the poor! Welcome aboard!

Please note that this is still some alpha-level software. Pull requests are
welcome!

Installation
------------

#. Apply patch ``patches/objtool-coverage.patch`` on top of Linux Kernel tree
   commmit c1d61e7fe3760851319138550efb732273ab2e57.

#. Build objtool::

	cd tools/objtool
	make
	...

#.  Use ``objtool coverage`` to get a list of jump points for an executable::

	cp objtool objtool1
	objtool coverage --no-kpatch objtool1 > ~/output.test

#. Make ``poormanbts``::

	make
	...

#. Use ``./poormanbts ~/output.test ~/linux/tools/objtool1`` to generate
   branching report for the code.
