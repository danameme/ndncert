LIBS = -lndn-cxx -lboost_system -lpthread -lndncertclientshlib
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib
NDNCERT_HEADERS = /usr/local/include/ndncert/ 

all:	edge-node.o
	g++ -std=c++14 $(SH_LIB_PATH) edge-node.o -o edge-node $(LIBS)

edge-node.o:	edge-node.cpp
	g++ -std=c++14 -I $(NDNCERT_HEADERS) -c edge-node.cpp -o edge-node.o

clean:
	rm *.o
