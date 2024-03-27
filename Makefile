all: encrypt decrypt

encrpyt: encrypt.o io.o aes.o field.o
	gcc -Wall -std=c99 encrypt.o io.o aes.o field.o -o encrypt

decrypt: decrypt.o io.o aes.o field.o
	gcc -Wall -std=c99 decrypt.o io.o aes.o field.o -o decrypt

aesTest: aesTest.o aes.o field.o
	gcc -Wall -std=c99 aesTest.o aes.o field.o -o aesTest

fieldTest: fieldTest.o field.o
	gcc -Wall -std=c99 fieldTest.o field.o -o fieldTest

encrypt.o: encrypt.c io.h aes.h
	gcc -Wall -std=c99 -g encrypt.c -c

decrypt.o: decrypt.c io.h aes.h
	gcc -Wall -std=c99 -g decrypt.c -c

io.o: io.c io.h field.h
	gcc -Wall -std=c99 io.c -c

aes.o: aes.c aes.h field.h
	gcc -Wall -std=c99 aes.c -c

field.o: field.c field.h
	gcc -Wall -std=c99 field.c -c

fieldTest.o: fieldTest.c field.h
	gcc -Wall -std=c99 fieldTest.c -c

aesTest.o: aesTest.c aes.h
	gcc -Wall -std=c99 aesTest.c -c

clean:
	rm -f *.o
	rm -f output.txt
	rm -f *.gch
	rm -f fieldTest
	rm -f aesTest