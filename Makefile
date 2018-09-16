
CFLAGS += -g
CPPFLAGS += -Ilibcare/src
LDLIBS += $(shell pkg-config --libs libunwind libunwind-ptrace)

all: poormanbts objtool kmod

objtool: tools/objtool/objtool
	cp $^ $@

tools/objtool/objtool: FORCE
	make -C $(dir $@)

poormanbts:	poormanbts.o 		\
		common.o		\
		libcare/src/libcare.a

libcare/src/libcare.a: libcare/src/*.c libcare/src/*.h
	make -C libcare/src libcare.a

clean:
	rm -f poormanbts poormanbts.o
	make -C libcare/src clean

kmod: FORCE
	make -C kmod

FORCE:
