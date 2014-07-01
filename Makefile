VERSION = NDEBUG
# VERSION = DEBUG
CC = clang
MAKE = make
CFLAGS = -Wall -Wextra -std=gnu99 -D$(VERSION) -c
EXECUTABLE = tcp_reassembler

ifeq ($(VERSION), DEBUG)
  CFLAGS += -g -Wno-unused-parameter
else
  CFLAGS += -O2 -Wno-parentheses
endif
export


all:
	cd lib && $(MAKE);
	cd src && $(MAKE);
	mv src/$(EXECUTABLE) .

clean:
	cd lib && $(MAKE) clean;
	cd src && $(MAKE) clean;
	rm -f $(EXECUTABLE)

run:
	./$(EXECUTABLE)

l:
	cd lib && $(MAKE)

d:
	make clean && make && make run
