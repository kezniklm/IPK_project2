#Makefile
#Riešenie IPK-projekt č.2
#Datum odovzdania: 17.4.2023
#Autor: Matej Keznikl
#Fakulta: Fakulta informačných technológií VUT v Brne (FIT VUT)
#Prelozene: GCC 11.3.0
#Testované na zariadeniach s operačnými systémami: Ubuntu 20.04, Debian 10, Cent OS 7,...
#Popis: Makefile pre IPK-projekt č.2

CC = gcc
CFLAGS = -std=c18 -pedantic -Wextra -Wextra -g -fcommon -D_DEFAULT_SOURCE -lpcap 

.PHONY: error.o args.o ipk-sniffer.o ipk-sniffer zip clean

ipk-sniffer: error.o args.o ipk-sniffer.o
	$(CC) $(CFLAGS) error.o args.o ipk-sniffer.o -o ipk-sniffer -lpcap 

error.o: error.h error.c 
	$(CC) $(CFLAGS) -c error.c -o error.o

args.o: args.h args.c
	$(CC) $(CFLAGS) -c args.c -o args.o

ipk-sniffer.o: ipk-sniffer.h
	$(CC) $(CFLAGS) -c ipk-sniffer.c -o ipk-sniffer.o

zip:
	zip -r xkezni01 * .gitignore
	
clean:
	rm -f ipk-sniffer
	rm -f xkezni01.zip
	rm -f *.o 