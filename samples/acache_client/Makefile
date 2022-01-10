.PHONY: client  clean

CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -g


OBJ = main.o connect.o
client: ${OBJ}
	$(CC) $(CFLAGS)  $^  -o acache_client
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f *.o acache_client
