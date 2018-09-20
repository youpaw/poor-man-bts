
CFLAGS += -g
CPPFLAGS += -Ilibcare/src -Itools/objtool/arch/x86/include
LDLIBS += $(shell pkg-config --libs libunwind libunwind-ptrace)

all: poormanbts objtool kmod

objtool: tools/objtool/objtool
	cp $^ $@

tools/objtool/%: FORCE
	make -C tools/objtool

poormanbts: LDLIBS += -lelf
poormanbts:	poormanbts.o 			\
		common.o			\
		libcare/src/libcare.a		\
		tools/objtool/arch/x86/decode.o \
		tools/objtool/elf.o

libcare/src/libcare.a: libcare/src/*.c libcare/src/*.h
	make -C libcare/src libcare.a

clean:
	rm -f poormanbts poormanbts.o
	make -C libcare/src clean

kmod: FORCE
	make -C kmod

FORCE:

test: poormanbts objtool
	./objtool coverage ./objtool > output.test
	./poormanbts ./output.test ./objtool
