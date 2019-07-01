LIBS = -lndn-cxx -lboost_system -lpthread -lndncertclientshlib
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib
NDNCERT_HEADERS = /usr/local/include/ndncert/

all:	discoveryHub.o
	g++ -std=c++14 $(SH_LIB_PATH) discoveryHub.o -o discoveryHub $(LIBS)

discoveryHub.o:		discoveryHub.cpp
	g++ -std=c++14 -I $(NDNCERT_HEADERS) -c discoveryHub.cpp -o discoveryHub.o

clean:
	rm *.o discoveryHub
