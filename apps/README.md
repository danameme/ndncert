Application Documentation
=========================

## Setup

ndncert installation:

    ./waf configure
    ./waf
    sudo ./waf install
    # if Linux, will also need `sudo ldconfig`

We assume that all nodes are connected to the same network reachable through multicast face(s), including ethernet multicast and IP/UDP multicast.

### Execution

We will execute the programs on each device in the order of CA device, MT device, EN device.

On CA device, prepare configuration, generate self-signed key, and run two programs.

Example of CA config (`ca.conf`):

    {
      "ca-list":
      [
        {
            "ca-prefix": "/ndn/ice-ar/demo1",
            "issuing-freshness": "720",
            "validity-period": "360",
            "ca-info": "Demo1 CA",
            "probe": "yes",
            "supported-challenges":
            [
                { "type": "LOCATION" }
            ]
        }
      ]
    }

Creating keys for this CA in a dedicated folder `/foobar`

    HOME=/foobar ndnsec-keygen -t rsa /ndn/ice-ar/demo1

Run CAs daemons:

    HOME=/foobar ndncert-ca-server -f ca.conf
    HOME=/foobar icear-ca

On MT device:

    icear-mt

    # or to see debugging of NDN packet exchanges
    # NDN_LOG=ndn.Face=ALL icear-mt
