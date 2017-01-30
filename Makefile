INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib

myvpnserver:miniVPNs.o function.o
	gcc -I$(INC) -L$(LIB) miniVPNs.o function.o -o myvpnserver -pthread -lm -lssl -lcrypto -ldl
function.o:function.c function.h
	gcc -I$(INC) -L$(LIB) -c function.c -o function.o
miniVPNs.o:miniVPNs.c function.h
	gcc -I$(INC) -L$(LIB) -c miniVPNs.c -o miniVPNs.o

clean:
	rm *.o
