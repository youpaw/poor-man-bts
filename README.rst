Poor Man's BTS
==============

#. Apply patch `patches/objtool-coverage.patch` on top of Linux Kernel tree
   commmit c1d61e7fe3760851319138550efb732273ab2e57.

#. Build objtool::

	cd tools/objtool
	make
	...

#.  Use `objtool coverage` to get a list of jump points for an executable::

	cp objtool objtool1
	objtool coverage --no-kpatch objtool1 > ~/output.test

#. Make `poormanbts`::

	make
	...

#. Use `./poormanbts ~/output.test ~/linux/tools/objtool1` to generate
   branching report for the code.
