LIBS = -lndn-cxx -lboost_system -lpthread -lndncertclientshlib
NDNCERT_HEADERS = /usr/local/include/ndncert/
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib


all:	auto-discovery.o
	g++ -std=c++14 $(SH_LIB_PATH) auto-discovery.o -o auto-discovery $(LIBS)

auto-discovery.o:	auto-discovery.cpp
	g++ -std=c++14 -I $(NDNCERT_HEADERS) -c auto-discovery.cpp

clean:
	rm *.o
