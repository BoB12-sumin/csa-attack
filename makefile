CC = g++
CFLAGS = -Wall
LDLIBS = -lpcap

all:csa-attack

mac.o : mac.h mac.cpp

main.o: beacon.h main.cpp

csa-attack: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f csa-attack *.o