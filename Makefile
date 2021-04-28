CC = gcc
CFLAGS = -O4 -Wall -I ./include

all: layer

layer: client.o server.o
		gcc -o client.out client.o
		gcc -o server.out server.o

client: client.c
		gcc -o client.out client.c

server: server.c
		gcc -o sever.out server.c

clean:; rm -f *.o *.out *~ server_socket