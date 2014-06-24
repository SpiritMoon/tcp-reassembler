VERSION = DEBUG
# VERSION = NDEBUG
CC = clang
MAKE = make
CFLAGS = -Wall -Wextra -std=gnu99 -D$(VERSION) -c

ifeq ($(VERSION), DEBUG)
  CFLAGS += -g -Wno-unused-parameter
else
  CFLAGS += -O2 -Wno-parentheses
endif
export


all:
	cd lib && $(MAKE);
	cd src && $(MAKE);
	mv src/main main;

clean:
	cd lib && $(MAKE) clean;
	cd src && $(MAKE) clean;

run:
	./$(EXECUTABLE)

l:
	cd lib && $(MAKE)

d:
	make clean && make && make run
