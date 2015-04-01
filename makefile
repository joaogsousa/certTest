all: program

program: main_test_cert.o b64.o
	gcc main_test_cert.o b64.o  -lb64 -lmiracl -lssl -lcrypto -o certTest 

clean:

b64.o: b64.c
	gcc b64.c -c
	
main_test_cert.o: main_test_cert.c
	gcc main_test_cert.c -c

execute: cert1.pem cert2.pem
	certTest cert1.pem cert2.pem

help:
	@echo "Use make execute to execute with default certificates cert1 and cert2, simply make to compile and make clean to clean!"
