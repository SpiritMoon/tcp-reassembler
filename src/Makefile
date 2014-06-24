LIBDIR = ../lib
CFLAGS += -I$(LIBDIR)
LDFLAGS = -lpcap -lz -L$(LIBDIR)
SOURCES = main.c http.c http_parser.c tcp.c udp.c ip.c network.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = main


all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBDIR)/*.o -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o ../$(EXECUTABLE)
