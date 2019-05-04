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
//#include <iostream>
#include <memory>
#include <stdexcept>
//#include <string>
#include <array>
#include <stdio.h>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include "ndncert-client-shlib.hpp"
#include "auto-client-shlib.hpp"

using namespace ndn::security::v2;

// Globals
int thiscount = 1;
std::string AP_Namespace;
std::string consumerIdentity = "prod2";
std::string namespace_prefix = "/ndn/AP40/";
std::string challenge_type = "NOCHALL";
ndn::security::v2::Certificate dataCert;
ndn::security::v2::Certificate trustAnchor;

using namespace std;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Consumer : noncopyable
{
public:



  void
  run()
  {
	
    Interest interest(Name("/ndn/nmsu/cs"));
    interest.setInterestLifetime(4_s); // 2 seconds
    interest.setMustBeFresh(true);
    
    auto identity = m_keyChain.getPib().getDefaultIdentity();
    auto cert = identity.getDefaultKey().getDefaultCertificate();

    //m_keyChain.sign(interest);
    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));

    //std::cout << "Sending " << interest << std::endl;

    //m_keyChain.sign(interest,signingByCertificate(cert));
    std::cout << ">> Sending Interest: " << interest << std::endl;
    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();

    return;
  }

  void 
  run_autoconfig()
  {
	AutoClientShLib cl;
        AP_Namespace = cl.RunAutoClient("wlan0");
        std::cout << "XXXX " << AP_Namespace << std::endl;
        return;
  }

  void
  run_ndncert()
  {
	NdnCertClientShLib cl;
	std::cout << AP_Namespace << consumerIdentity << std::endl;
        int result = cl.RunNdnCertClient(AP_Namespace, consumerIdentity, challenge_type);


        return;
  }

  void
  get_data_cert()
  {
    std::string prodNamespace = "/ndn/AP/";
    std::string prodName = "producer";
    Interest interest(Name(prodNamespace + "CA/_CERT/_DATACERT/" + prodName));
    interest.setInterestLifetime(2_s); // 2 seconds
    interest.setMustBeFresh(true);

    m_face2.expressInterest(interest,
                           bind(&Consumer::onDataCert, this,  _1, _2),
                           bind(&Consumer::onNackCert, this, _1, _2),
                           bind(&Consumer::onTimeoutCert, this, _1));

    std::cout << "\n >> Sending Interest to retrieve CERTIFICATE: " << interest << std::endl;
    // processEvents will block until the requested data received or timeout occurs
    m_face2.processEvents();
  
    return;
  }

private:

  void
  onDataCert(const Interest& interest, const Data& data)
  {
	ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
	dataCert = cert;

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
    std::cout << "data name " << data.getSignature().getKeyLocator().getName() << std::endl;
    //Get certificate from CA for the name in received data packet
    //get_data_cert();

    if(ndn::security::verifySignature(data, dataCert)) {
	std::cout << "\n<< Received Data: " << data << std::endl;
	std::cout << "\nData Verification SUCCESSFUL!!!\n";
    }
    else {
	    std::cout << "\n<< Received Data: " << data << std::endl;
    	std::cout << "\nData Received. Verification FAILED!!!\n";
    }
    
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {

	  if(nack.getReason() == lp::NackReason::INVALID_CERT){
		std::cout << "Got invalid cert. Starting ndncert...\n";
		system(caName.c_str());
		
		sleep(1);

		//Set new signing identity that we got from CA
		auto ident = m_keyChain.getPib().getIdentity(Name(certIdentity));
		m_keyChain.setDefaultIdentity(ident);

		//reset count so app will start from beginning
		thiscount = 0;
	  }

	  if(nack.getReason() == lp::NackReason::NO_ROUTE){
		std::cout << "Got NoRoute. Starting discovery\n";

		// Assume pi reconnects to AP and ndn-autoconfig works the first time

		AutoClientShLib autocl;
        	AP_Namespace = autocl.RunAutoClient("wlan0");

		NdnCertClientShLib ndncertcl;
        	int result = ndncertcl.RunNdnCertClient(AP_Namespace, consumerIdentity, challenge_type);

		//reset count to restart app
		thiscount = 0;
	}

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
  std::string certIdentity;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  if (argc == 3) {
          namespace_prefix = argv[1];
          consumerIdentity = argv[2];
  }

  ndn::examples::Consumer consumer;
  try {

    //consumer.run_autoconfig();
    //consumer.run_ndncert();

    //while(thiscount < 20){
    	consumer.run();
    	thiscount++;
    //}
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
