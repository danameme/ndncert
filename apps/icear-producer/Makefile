LIBS = -lndn-cxx -lboost_system -lndncertclientshlib -lautodiscoveryshlib -lresolv
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib
NDNCERT_HEADERS = /usr/local/include/ndncert/
AUTOCONFIG_HEADERS = /usr/local/include/NFD/ndn-autoconfig/ 

all:	ICE-AR-Producer.o discoveryHub.o
	g++ $(SH_LIB_PATH) ICE-AR-Producer.o -o ICE-AR-Producer $(LIBS)
	g++ $(SH_LIB_PATH) discoveryHub.o -o discoveryHub $(LIBS)

ICE-AR-Producer.o:	ICE-AR-Producer.cpp
	g++ -I $(AUTOCONFIG_HEADERS) -I $(NDNCERT_HEADERS) -c ICE-AR-Producer.cpp -o ICE-AR-Producer.o

discoveryHub.o:		discoveryHub.cpp
	g++ -I $(AUTOCONFIG_HEADERS) -I $(NDNCERT_HEADERS) -c discoveryHub.cpp -o discoveryHub.o

clean:
	rm *.o
