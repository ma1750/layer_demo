CC = gcc
CFLAGS = -O2 -Wall -I ./includes

all: layer

layer: client.o md5c.o server.o
		$(CC) $(CFLAGS) -o client.out client.o md5c.o
		$(CC) $(CFLAGS) -o server.out server.o md5c.o

client: client.o md5c.o
		$(CC) $(CFLAGS) -o client.out client.c md5c.c

server: server.o md5c.o
		$(CC) $(CFLAGS) -o server.out server.c

clean:; rm -f *.o *.out *~ server_socket