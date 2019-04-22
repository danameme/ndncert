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
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <fstream>
#include <iostream>

#include "ndncert-client-shlib.hpp"
//#include "auto-client-shlib.hpp"

std::string AP_Namespace;
std::string producerIdentity = "prod0";
std::string namespace_prefix = "/ndn/AP40/";
std::string challenge_type = "NOCHALL";

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Producer : noncopyable
{
public:
  void
  run()
  {
    std::cout << "\nServing data for " << namespace_prefix << producerIdentity << std::endl;

    m_face.setInterestFilter(namespace_prefix + producerIdentity,
                             bind(&Producer::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

  void
  run_autoconfig()
  {
	  //AutoClientShLib cl;

        system("ndn-autoconfig -i eth0 > temp_out.txt 2>&1");
        system("grep \"CA Namespace\" temp_out.txt > temp_out2.txt 2>&1");
        std::ifstream file("temp_out2.txt");
        std::getline(file, AP_Namespace);
        file.close();
        std::string namesp = AP_Namespace.substr(AP_Namespace.find(":") + 1); //remove description
        AP_Namespace = namesp.substr(namesp.find_first_not_of(" ")); //trim leading spaces
        system("rm temp_out*");
        return;
  }

  void
  run_ndncert()
  {
	NdnCertClientShLib cl;
        int result = cl.NdnCertRunClient(AP_Namespace, producerIdentity, challenge_type);
	
	return;
  }


private:
  void
  onInterest(const InterestFilter& filter, const Interest& interest)
  {
    std::cout << "<< I: " << interest << std::endl;

    // Create new name, based on Interest's name
    Name dataName(interest.getName());
    dataName
      .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

    static const std::string content = "TEST CONTENT";

    // Create Data packet
    shared_ptr<Data> data = make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); // 10 seconds
    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());

    // Sign Data packet
    m_keyChain.sign(*data, ndn::security::signingByIdentity(Name(namespace_prefix + producerIdentity)));

    // Return Data packet to the requester
    std::cout << ">> D: " << *data << std::endl;
    m_face.put(*data);
  }


  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  if (argc == 3) {
	  namespace_prefix = argv[1];
	  producerIdentity = argv[2];
  }

  ndn::examples::Producer producer;
  try {

    producer.run_autoconfig();

    producer.run_ndncert();

    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
