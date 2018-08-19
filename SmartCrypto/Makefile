CC=gcc
CFLAGS=-I. -I/opt/local/include/ -std=gnu99
LDFLAGS=-lssl -lcrypto -L/opt/local/lib/

smartcrypto: main.o crypto.o aes.o 
	$(CC) -o smartcrypto main.o crypto.o aes.o $(CFLAGS) $(LDFLAGS)
clean:
	-rm ./*.o smartcrypto
