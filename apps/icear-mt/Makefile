LIBS = -lndn-cxx -lboost_system -lpthread -lndncertclientshlib
NDNCERT_HEADERS = /usr/local/include/ndncert/
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib


all:	mobile-terminal.o
	g++ -std=c++14 $(SH_LIB_PATH) mobile-terminal.o -o mobile-terminal $(LIBS)

mobile-terminal.o:	mobile-terminal.cpp
	g++ -std=c++14 -I $(NDNCERT_HEADERS) -c mobile-terminal.cpp

clean:
	rm *.o
