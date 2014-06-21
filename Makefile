VERSION=DEBUG
CC=cc
CFLAGS= -Wall -Wextra -std=c99 -D$(VERSION) -g -c
PDEFINE= -D_BSD_SOURCE
LDFLAGS= -lpcap -lz
SOURCES= main.c myhttp.c http_parser.c mytcp.c myudp.c myip.c mynetwork.c util.c hashtbl.c list.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=main

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(EXECUTABLE)

run:
	./$(EXECUTABLE)

d:
	make clean && make && make run

