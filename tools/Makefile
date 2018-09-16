# SPDX-License-Identifier: GPL-2.0
# Some of the tools (perf) use same make variables
# as in kernel build.
export srctree=
export objtree=

include scripts/Makefile.include

help:
	@echo 'Possible targets:'
	@echo ''
	@echo '  objtool                - an ELF object analysis tool'
	@echo ''
	@echo 'You can do:'
	@echo ' $$ make -C tools/ <tool>_install'
	@echo ''
	@echo '  from the kernel command line to build and install one of'
	@echo '  the tools above'
	@echo ''
	@echo '  $$ make tools/all'
	@echo ''
	@echo '  builds all tools.'
	@echo ''
	@echo '  $$ make tools/install'
	@echo ''
	@echo '  installs all tools.'
	@echo ''
	@echo 'Cleaning targets:'
	@echo ''
	@echo '  all of the above with the "_clean" string appended cleans'
	@echo '    the respective build directory.'
	@echo '  clean: a summary clean target to clean _all_ folders'

all: objtool

objtool: FORCE
	$(call descend,$@)

objtool_clean build_clean:
	$(call descend,$(@:_clean=),clean)

libsubcmd_clean:
	$(call descend,lib/subcmd,clean)

clean: objtool_clean build_clean libsubcmd_clean

.PHONY: FORCE
