CXXFLAGS = -std=c++14 $(shell pkg-config --cflags libndn-cxx) -I/usr/local/include/ndncert
LDLFAGS = $(shell pkg-config --libs libndn-cxx) -lndncertclientshlib -lcryptopp
NDNCERT_HEADERS = /usr/local/include/ndncert/
SH_LIB_PATH = -L /usr/local/lib -Wl,-rpath=/usr/local/lib


all: mobile-terminal
	
mobile-terminal: mobile-terminal.o
	$(CXX) $(LDLFAGS) $< -o $@

#	g++ -std=c++14 $(SH_LIB_PATH) mobile-terminal.o -o mobile-terminal $(LIBS)
#
#mobile-terminal.o:	mobile-terminal.cpp
#	g++ -std=c++14 -I $(NDNCERT_HEADERS) -c mobile-terminal.cpp

clean:
	rm *.o 
	rm mobile-terminal
