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

