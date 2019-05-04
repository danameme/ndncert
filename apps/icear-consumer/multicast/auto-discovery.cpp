/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2017,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "auto-discovery.hpp"
#include <boost/lexical_cast.hpp>
#include <ndn-cxx/encoding/tlv-nfd.hpp>
#include "ndncert-client-shlib.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

ndn::Face face;   
ndn::Face m_face2;
ndn::security::KeyChain keyChain;
std::string caName;
std::string challengeType = "NOCHALL";
std::string identity = "cons5";


namespace ndn {
namespace autodiscovery {

using nfd::ControlParameters;
using nfd::ControlResponse;

static const Name HUB_DISCOVERY_PREFIX("/localhop/ndn-autoconf/CA");
static const uint64_t HUB_DISCOVERY_ROUTE_COST(1);
static const time::milliseconds HUB_DISCOVERY_ROUTE_EXPIRATION = time::seconds(30);
static const time::milliseconds HUB_DISCOVERY_INTEREST_LIFETIME = time::seconds(4);

AutoDiscovery::AutoDiscovery(Face& face, nfd::Controller& controller)
  : m_face(face)
  , m_controller(controller)
{
}

void
  AutoDiscovery::RunNdncert()
  {
	NdnCertClientShLib cl;
	std::cout << caName <<identity << std::endl;
        int result = cl.RunNdnCertClient(caName, identity, challengeType);
        return;
  }

void
AutoDiscovery::doStart()
{
  nfd::FaceQueryFilter filter;
  filter.setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);

  m_controller.fetch<nfd::FaceQueryDataset>(
    filter,
    bind(&AutoDiscovery::registerHubDiscoveryPrefix, this, _1),
    [this] (uint32_t code, const std::string& reason) {
      this->fail("Error " + to_string(code) + " when querying multi-access faces: " + reason);
    });
}

void
AutoDiscovery::registerHubDiscoveryPrefix(const std::vector<nfd::FaceStatus>& dataset)
{
  if (dataset.empty()) {
    this->fail("No multi-access faces available");
    return;
  }

  m_nRegs = dataset.size();
  m_nRegSuccess = 0;
  m_nRegFailure = 0;

  for (const auto& faceStatus : dataset) {
    ControlParameters parameters;
    parameters.setName(HUB_DISCOVERY_PREFIX)
              .setFaceId(faceStatus.getFaceId())
              .setCost(HUB_DISCOVERY_ROUTE_COST)
              .setExpirationPeriod(HUB_DISCOVERY_ROUTE_EXPIRATION);

    m_controller.start<nfd::RibRegisterCommand>(
      parameters,
      [this] (const ControlParameters&) {
        ++m_nRegSuccess;
        afterReg();
      },
      [this, faceStatus] (const ControlResponse& resp) {
        std::cerr << "Error " << resp.getCode() << " when registering hub discovery prefix "
                  << "for face " << faceStatus.getFaceId() << " (" << faceStatus.getRemoteUri()
                  << "): " << resp.getText() << std::endl;
        ++m_nRegFailure;
        afterReg();
      });

  }
}

void
AutoDiscovery::afterReg()
{
  if (m_nRegSuccess + m_nRegFailure < m_nRegs) {
    return; // continue waiting
  }
  if (m_nRegSuccess > 0) {
    this->setStrategy();
  }
  else {
    this->fail("Cannot register hub discovery prefix for any face");
  }
}

void
AutoDiscovery::setStrategy()
{
  ControlParameters parameters;
  parameters.setName(HUB_DISCOVERY_PREFIX)
            .setStrategy("/localhost/nfd/strategy/multicast"),

  m_controller.start<nfd::StrategyChoiceSetCommand>(
    parameters,
    bind(&AutoDiscovery::requestHubData, this),
    [this] (const ControlResponse& resp) {
      this->fail("Error " + to_string(resp.getCode()) + " when setting multicast strategy: " +
                 resp.getText());
    });
}


void
AutoDiscovery::startListener(){

    m_face2.setInterestFilter("/ndn/ucla/cs",
                             bind(&AutoDiscovery::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&AutoDiscovery::onRegisterFailed, this, _1, _2));
    m_face2.processEvents();

}


void
  AutoDiscovery::onInterest(const InterestFilter& filter, const Interest& interest)
  {
    
    std::cout << "<< Received interest: " << interest << std::endl;

    // Create new name, based on Interest's name
    Name dataName(interest.getName());
    dataName
      .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

    std::string content = "test";
    // Create Data packet
    shared_ptr<Data> data = make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); // 10 seconds
    data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());

    // Sign Data packet
    keyChain.sign(*data, ndn::security::signingByIdentity(Name(caName +"/"+identity)));

    // Return Data packet to the requester
    std::cout << ">> D: " << *data << std::endl;
    m_face2.put(*data);
  }


  void
  AutoDiscovery::onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

void
AutoDiscovery::requestHubData()
{
  Interest interest(HUB_DISCOVERY_PREFIX);
  interest.setInterestLifetime(HUB_DISCOVERY_INTEREST_LIFETIME);
  interest.setMustBeFresh(true);

  std::cout << "Sending interest via multicast... " << interest << std::endl;

  m_face.expressInterest(interest,
    [this] (const Interest&, const Data& data) {
      const Block& content = data.getContent();
      content.parse();
      std::cout << data.getSignature().getKeyLocator().getName() << std::endl;
      ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
      if(ndn::security::verifySignature(data,cert)){
        std::cout << "Client certificate verified by trust anchor!!!";
      }
      std::cout << cert << std::endl;

      // Get CA namespace from Keylocator
      KeyLocator keyLocator = cert.getSignature().getKeyLocator();
      std::string tempName = keyLocator.getName().toUri();
      caName = tempName.substr(0,tempName.find("KEY")-1);
      std::cout << caName << std::endl;

      std::cout << "Fetching client certificate\n";
      RunNdncert();
      std::cout << "Starting Listener...\n";
      startListener();
      
    },
    [this] (const Interest&, const lp::Nack& nack) {
      this->fail("Nack-" + boost::lexical_cast<std::string>(nack.getReason()) + " when retrieving hub Data");
    },
    [this] (const Interest&) {
      this->fail("Timeout when retrieving hub Data");
    });

}

void
AutoDiscovery::fail(const std::string& msg)
{
  std::cerr << "Multicast discovery failed: " << msg << std::endl;
  this->onFailure(msg);
}

void
AutoDiscovery::succeed(const FaceUri& hubFaceUri)
{
  std::cerr << "Multicast discovery succeeded with " << hubFaceUri << std::endl;
  this->onSuccess(hubFaceUri);
}

void
AutoDiscovery::provideHubFaceUri(const std::string& s)
{

std::cout << "provideHubFaceUri..." << std::endl;

  FaceUri u;
  if (u.parse(s)) {
    this->succeed(u);
  }
  else {
    this->fail("Cannot parse FaceUri: " + s);
  }
}

} // namespace autodiscovery
} // namespace ndn


int
main(int argc, char** argv)
{
	ndn::nfd::Controller controller(face, keyChain);
	ndn::autodiscovery::AutoDiscovery autodisc(face, controller);

	autodisc.doStart();
	face.processEvents();

	return 0;

}
