CC= gcc

all: Encryp_SW.o libencrypt_decrypt.so
	$(CC) Encryp_SW.o -Wl,-rpath=. -L. -lencrypt_decrypt -lcrypto -o facsat2_encryp

Encryp_SW.o: Encryp_SW.c
	$(CC) Encryp_SW.c  -c -o Encryp_SW.o

encrypt_decrypt.o: encrypt_decrypt.c
	$(CC) encrypt_decrypt.c -fPIC -c -o encrypt_decrypt.o

libencrypt_decrypt.so: encrypt_decrypt.o
	$(CC) -shared encrypt_decrypt.o -o libencrypt_decrypt.so

.PHONY: clean
clean:
	rm -rf *.o *.so facsat2_encryp *_Encryp