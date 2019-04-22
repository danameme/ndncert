LIBS = -lndn-cxx -lboost_system -lndncertclientshlib
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib
NDNCERT_HEADERS = /usr/local/include/ndncert

all:	ICE-AR-Producer.o
	g++ $(SH_LIB_PATH) ICE-AR-Producer.o -o ICE-AR-Producer $(LIBS)

ICE-AR-Producer.o:	ICE-AR-Producer.cpp
	g++ -I $(NDNCERT_HEADERS) -c ICE-AR-Producer.cpp -o ICE-AR-Producer.o

clean:
	rm *.o
