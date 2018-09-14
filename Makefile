
CPPFLAGS += -Ilibcare/src
LDLIBS += $(shell pkg-config --libs libunwind libunwind-ptrace)

poormanbts:	poormanbts.o 		\
		common.o		\
		libcare/src/libcare.a

libcare/src/libcare.a: libcare/src/*.c libcare/src/*.h
	make -C libcare/src libcare.a

clean:
	rm -f poormanbts poormanbts.o
	make -C libcare/src clean
