#GCC=gcc -g -Wall -Wextra -pedantic -std=gnu11
GCC=gcc -g -Wall -Wextra -pedantic -std=gnu11
LD_FLAGS= -lpthread -lm

all: peer peerchat

rebuild: clean all

compsys_helpers.o: compsys_helpers.c compsys_helpers.h
	$(GCC) -c $< -o $@

common.o: common.c common.h
	$(GCC) -c $< -o $@

peer: peer.c peer.h common.o compsys_helpers.o sha256.o
	$(GCC) $< *.o -o $@ $(LD_FLAGS)

peerchat: peerchat.c peer.h common.o compsys_helpers.o sha256.o
	$(GCC) $< *.o -o $@ $(LD_FLAGS)

sha256.o : sha256.c sha256.h
	$(GCC) -c $< -o $@

zip: ../../src.zip

../../src.zip:
	make clean
	cd ../.. && zip -r handout/src.zip handout/src/Makefile handout/src/*.c handout/src/*.h handout/python/*.py handout/python/*/*.py

clean:
	rm -rf *.o peer peerchat sha256 vgcore*
