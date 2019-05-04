LIBS = -lndn-cxx -lboost_system -lndncertclientshlib -lautodiscoveryshlib -lresolv
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib
NDNCERT_HEADERS = /usr/local/include/ndncert/
AUTOCONFIG_HEADERS = /usr/local/include/NFD/ndn-autoconfig/ 

all:	ICE-AR-Consumer.o mobileTerminal.o
	g++ $(SH_LIB_PATH) ICE-AR-Consumer.o -o ICE-AR-Consumer	$(LIBS)
	g++ $(SH_LIB_PATH) mobileTerminal.o -o mobileTerminal	$(LIBS)


mobileTerminal.o:	mobileTerminal.cpp
	g++ -I $(AUTOCONFIG_HEADERS) -I $(NDNCERT_HEADERS) -c mobileTerminal.cpp -o mobileTerminal.o

ICE-AR-Consumer.o:	ICE-AR-Consumer.cpp
	g++ -I $(AUTOCONFIG_HEADERS) -I $(NDNCERT_HEADERS) -c ICE-AR-Consumer.cpp -o ICE-AR-Consumer.o

clean:
	rm *.o
