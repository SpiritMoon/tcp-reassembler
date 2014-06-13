all: main

main: main.o util.o hashtbl.o list.o http_parser.o
	cc -std=c99 -o main util.o http_parser.o hashtbl.o list.o main.o -lpcap -lz -Wall

util.o: util.c util.h
	cc -std=c99 -o util.o -c util.c -g

http_parser.o: http_parser.c http_parser.h
	cc -std=c99 -o http_parser.o -c http_parser.c -g

hashtbl.o: hashtbl.c hashtbl.h
	cc -std=c99 -o hashtbl.o -c hashtbl.c -g

list.o: list.c list.h
	cc -std=c99 -o list.o -c list.c -g

main.o: main.c main.h hashtbl.h 
	cc -std=c99 -o main.o -c main.c -g 

clean:
	rm -rf *.o main a.out 

run:
	./main

d:
	make clean && make && make run
