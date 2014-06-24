LDFLAGS = -nostartfiles
SOURCES = util.c hash.c file.c
OBJECTS = $(SOURCES:.c=.o)


all: $(OBJECTS)

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f *.o
