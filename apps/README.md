Application Documentation
=========================

There are 3 apps in the following directories used to test the security feature: icear-mt runs on the mobile terminal, icear-en runs on the edge node, and icear-ca runs on the CA (together with NDNCert).

CA is assumed to be the Trust Anchor for this use-case

The mobile terminal app in icear-mt performs the following actions:

- Mobile terminal dicovers Trust Anchor
- Mobile terminal requests certifcate from CA (NDNCert)
- Mobile terminal verifies certificate received using Trust Anchor
- Mobile terminal starts listening for interest packets. When it receives interest, it generates dummy data and signs it with its certificate.

The edge node app in icear-en performs the following actions:

- Edge node discovers Trust Anchor
- Edge node sends interest to mobile terminal for data
- When edge node received data packet, it fetches certificate used to sign data packet from CA
- Edge node verifies the fetched certificate using the Trust Anchor
- On successfull verification of cerificate, edge node verifies data packet with the fetched certicate of the data packet.

The discovery hub app in icear-ca performs the following functions:

- Discover app receives interest for /localhop/ndn-autoconf/CA and responds with the default identity of the Trust Anchor (in this use-case, same as CA)


## Setup

Additional pre-requisites:
```
sudo apt-get install libcrypto++-dev libcrypto++-utils
```


ndncert installation:

```
./waf configure

Edit the build/config.log file and add -lcryptopp to the line:
out: -pthread -DBOOST_LOG_DYN_LINK -I/usr/local/include -L/usr/local/lib -pthread -lndn-cxx -lboost_system -lboost_program_options -lboost_chrono -lboost_date_time -lboost_filesystem -lboost_thread -lboost_log -lcrypto -lsqlite3 -lrt -lpthread

Edit the build/c4che/_cache.py file and add cryptopp to the following list:
LIB_NDN_CXX = [...]

./waf
sudo ./waf install
sudo ldconfig
```
Ensure that libndncertclientshlib.so exists in the /usr/local/lib directory.

On the device that will be running the CA server:
```
:~$ cd ndncert/apps/icear-ca
:~$ sudo cp ca.conf /usr/local/etc/ndncert/ca.conf
```
We make a self-signed certificate that serves as the trust anchor:
```
ndnsec-keygen -i /ndn/ucla/compSci/15
ndnsec-set-default -n /ndn/ucla/compSci/15
```

On the device that will be running the mobile terminal:
```
:~$ cd ndncert/apps/icear-mt
:~$ sudo cp client.conf /usr/local/etc/ndncert/client.conf
```

We assume that all nodes are connected to a dummy access point and have IP addresses.

We also assume the edge node has previously set up the faces/routes to the CA and mobile terminal:

```
nfdc face create udp://<CAaddress>
nfdc face create udp://<MTaddress>
nfdc route add /localhop/ndn-autoconf/CA <CAfaceID>
nfdc route add /ndn/ucla/cs/app/mobterm1 <MTfaceID>
```

Once the above steps have been completed, execute the Makefiles in the three directories located:

```
/ndncert/apps/icear-mt
/ndncert/apps/icear-en
/ndncert/apps/icear-ca
```

### Execution

We will execute the programs on each device in the order of CA device, MT device, EN device.

On CA device we will execute two programs:
```
ndncert-ca-server
ndncert/apps/icear-ca/discoveryHub
```

On MT device:
```
ndncert/apps/icear-mt/mobile-terminal
```

Once we see output from the mobile terminal that says it has started the listener, we can then execute the edge node program:
```
ndncert/apps/icear-en/edge-node
```





