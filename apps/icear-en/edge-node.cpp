/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */

#include <ndn-cxx/face.hpp>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <stdio.h>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include "ndncert-client-shlib.hpp"

using namespace ndn::security::v2;

// Global variables
int requestcount = 1;
std::string certNamespace;
std::string identity = "edgenode1";
std::string challengeType = "NOCHALL";
std::string dataNamespace = "/ndn/ucla/cs/app/mobterm1";
ndn::security::v2::Certificate dataCert;
ndn::security::v2::Certificate trustAnchor;

using namespace std;

namespace ndn {
namespace examples {

class Consumer : noncopyable
{
public:

  void GetTrustAnchor(){
       Interest interest(Name("/localhop/ndn-autoconf/CA"));
       interest.setInterestLifetime(4_s);
       interest.setMustBeFresh(true);
       m_face.expressInterest(interest,
                           bind(&Consumer::onDataDiscovery, this,  _1, _2),
                           bind(&Consumer::onNackDiscovery, this, _1, _2),
                           bind(&Consumer::onTimeoutDiscovery, this, _1));

	m_face.processEvents();  

  }

  void
  GetMobileTerminalData()
  {
	
    Interest interest(Name(dataNamespace.c_str()));
    interest.setInterestLifetime(4_s); // 2 seconds
    interest.setMustBeFresh(true);
    
    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));

    std::cout << "\n--------------------------------------\n";
    std::cout << ">> Sending Interest for Data: " << interest << std::endl;
    m_face.processEvents();

    return;
  }

  
  void
  RunNdncert()
  {
	NdnCertClientShLib cl;
	std::cout << certNamespace << "/" << identity << std::endl;
        int result = cl.RunNdnCertClient(certNamespace, identity, challengeType);
        return;
  }

  void
  GetDataCertificate()
  {
    Interest interest(Name(caName + "CA/_CERT/_DATACERT/" + consID));
    interest.setInterestLifetime(2_s); // 2 seconds
    interest.setMustBeFresh(true);

    m_face2.expressInterest(interest,
                           bind(&Consumer::onDataCert, this,  _1, _2),
                           bind(&Consumer::onNackCert, this, _1, _2),
                           bind(&Consumer::onTimeoutCert, this, _1));

    std::cout << "\n>> Retrieving data packet CERTIFICATE: " << interest << std::endl;
    m_face2.processEvents();
  
    return;
  }

private:

  void
  onDataDiscovery(const Interest& interest, const Data& data)
  {
        ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
        trustAnchor = cert;
	std::cout << "\n\nTrust Anchor certificate retrieved...\n" << cert << endl;
        return;
  }

  void
  onNackDiscovery(const Interest& interest, const lp::Nack& nack)
  {
        std::cout << "\nNACK Retrieving Cert.... \n" << interest.getName() << std::endl;
        return;
  }

  void
  onTimeoutDiscovery(const Interest& interest)
  {
          std::cout << "\nTIMEOUT Retrieving Cert.... \n" << interest.getName() << std::endl;
          return;
  }



  void
  onDataCert(const Interest& interest, const Data& data)
  {
	ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
	dataCert = cert;

	// Verify that certificate we received was signed by Trust Anchor
	if(ndn::security::verifySignature(data,trustAnchor)){
		std::cout << "Verified retrieved data packet certificate!!!\n";
	}
	else{
		std::cout << "Verification of certificate failed\n";
	}
	return;
  }

  void
  onNackCert(const Interest& interest, const lp::Nack& nack)
  {
	std::cout << "\nNACK Retrieving Cert.... \n" << interest.getName() << std::endl;
	return;
  }

  void
  onTimeoutCert(const Interest& interest)
  {
	  std::cout << "\nTIMEOUT Retrieving Cert.... \n" << interest.getName() << std::endl;
	  return;
  }

  void
  onData(const Interest& interest, const Data& data)
  {

    Name dataName = data.getSignature().getKeyLocator().getName();

    //We separate the name in the data signature so we can make a call to GetDataCertificate()
    caName = data.getSignature().getKeyLocator().getName().getSubName(0,dataName.size()-3).toUri()+"/";

    //We know that the 3rd to last component is the identity of the device we need to get a cert for
    consID = data.getSignature().getKeyLocator().getName()[-3].toUri();
    
    //Get certificate from CA for the name in received data packet
    std::cout << "Getting certiticate for... " << caName << consID << std::endl;

    // Get certificate used to sign data packet certifcate from CA
    GetDataCertificate();

    // Perform data packet verification
    if(ndn::security::verifySignature(data, dataCert)) {
	std::cout << "\n<< Received Data: \n" << data << std::endl;
	std::cout << "Data Packet Verification SUCCESSFUL!!!\n";
    }
    else {
	std::cout << "\n<< Received Data: \n" << data << std::endl;
    	std::cout << "Data Packet Verification FAILED!!!\n";
    }
    
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;

    return;
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
    return;
  }

private:
  KeyChain m_keyChain;
  Face m_face;
  Face m_face2;
  std::string caName;
  std::string consID;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  ndn::examples::Consumer en;
  try {

    en.GetTrustAnchor();

    while(requestcount < 5){
    	en.GetMobileTerminalData();
    	requestcount++;
    }
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
