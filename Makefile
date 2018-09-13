
CPPFLAGS += -Ilibcare/src
LDLIBS += $(shell pkg-config --libs libunwind libunwind-ptrace)

poormanbts: poormanbts.o 		\
	libcare/src/kpatch_process.o 	\
	libcare/src/kpatch_log.o	\
	libcare/src/kpatch_ptrace.o	\
	libcare/src/kpatch_coro.o	\
	libcare/src/kpatch_layout.o	\
	libcare/src/kpatch_object_file.o

libcare/%:
	make -C libcare
