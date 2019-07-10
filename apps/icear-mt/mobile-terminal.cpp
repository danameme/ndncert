/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "mobile-terminal.hpp"

#include <ndn-cxx/encoding/tlv-nfd.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

#include <iostream>
#include <boost/lexical_cast.hpp>
#include <boost/exception/diagnostic_information.hpp>

namespace ndn {
namespace autodiscovery {

using nfd::ControlParameters;
using nfd::ControlResponse;

static const Name HUB_DISCOVERY_PREFIX("/localhop/ndn-autoconf/CA");
static const uint64_t HUB_DISCOVERY_ROUTE_COST(1);
static const time::milliseconds HUB_DISCOVERY_ROUTE_EXPIRATION = 160_s;
static const time::milliseconds HUB_DISCOVERY_INTEREST_LIFETIME = 2_s;

AutoDiscovery::AutoDiscovery()
  : m_face(nullptr, m_keyChain)
  , m_controller(m_face, m_keyChain)
  , m_scheduler(m_face.getIoService())
{
}

void
AutoDiscovery::doStart()
{
  m_controller.start<nfd::FaceUpdateCommand>(
    nfd::ControlParameters()
      .setFlagBit(nfd::FaceFlagBit::BIT_LOCAL_FIELDS_ENABLED, true),
    [this] (const auto&...) {
      nfd::FaceQueryFilter filter;
      filter.setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);

      m_controller.fetch<nfd::FaceQueryDataset>(
        filter,
        bind(&AutoDiscovery::registerHubDiscoveryPrefix, this, _1),
        [this] (uint32_t code, const std::string& reason) {
          this->fail("Error " + to_string(code) + " when querying multi-access faces: " + reason);
        });
    },
    [this] (const auto&...) {
      this->fail("Cannot set FaceFlags bit");
    });

  m_face.processEvents();
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
    std::cerr << "Registered to " << m_nRegSuccess << " faces" << std::endl;
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
    [this] (const auto&...) { this->requestHubData(3); },
    [this] (const ControlResponse& resp) {
      this->fail("Error " + to_string(resp.getCode()) + " when setting multicast strategy: " +
                 resp.getText());
    });
}

void
AutoDiscovery::requestHubData(size_t retriesLeft)
{
  Interest interest(HUB_DISCOVERY_PREFIX);
  interest.setInterestLifetime(HUB_DISCOVERY_INTEREST_LIFETIME);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  std::cout << "Sending interest via multicast... " << interest << std::endl;

  m_face.expressInterest(interest,
    [this] (const Interest&, const Data& data) {

      const Block& content = data.getContent();
      content.parse();
      ndn::security::v2::Certificate cert(data.getContent().blockFromValue());

      std::cout << "\nTrust Anchor certificate retrieved...\n" << cert << std::endl;

      // if (ndn::security::verifySignature(data, cert)){
      //   std::cout << "Device certificate verified by trust anchor!!!\n";
      // }

      uint64_t faceId = 0;
      auto tag = data.getTag<lp::IncomingFaceIdTag>();
      if (tag != nullptr) {
        faceId = tag->get();
      }
      else {
        std::cerr << "Incoming data missing IncomingFaceIdTag" << std::endl;
      }

      std::cout << "Got data from FaceId " << faceId << std::endl;

      // Get CA namespace
      Name caName = cert.getName().getPrefix(-4);

      m_ndncertTool = std::make_unique<ndncert::LocationClientTool>(m_face, m_keyChain, caName, cert);

      // Get certificate to be used for signing data
      registerPrefixAndRunNdncert(caName, faceId);

      std::cerr << "END OF NDNCERT" << std::endl;
    },
    [this, retriesLeft] (const Interest&, const lp::Nack& nack) {
      std::cerr << "Got NACK: " << nack.getReason() << std::endl;
      if (retriesLeft > 0) {
        std::cerr << "   Retrying in 1 second..." << std::endl;

        m_scheduler.schedule(1_s, [=] {
            requestHubData(retriesLeft - 1);
          });
      }
    },
    [this, retriesLeft] (const Interest&) {
      std::cerr << "Request timed out" << std::endl;
      if (retriesLeft > 0) {
        std::cerr << "   Retrying..." << std::endl;
        requestHubData(retriesLeft - 1);
      }
    });
}

void
AutoDiscovery::fail(const std::string& msg)
{
  std::cerr << "Multicast discovery failed: " << msg << std::endl;
}

void
AutoDiscovery::succeed(const FaceUri& hubFaceUri)
{
  std::cerr << "Multicast discovery succeeded with " << hubFaceUri << std::endl;
}

void
AutoDiscovery::registerPrefixAndRunNdncert(const Name& caPrefix, uint64_t faceId)
{
  // register CA prefix
  ControlParameters parameters;
  parameters.setName(caPrefix)
    .setFaceId(faceId)
    .setCost(HUB_DISCOVERY_ROUTE_COST)
    .setExpirationPeriod(HUB_DISCOVERY_ROUTE_EXPIRATION);

  m_controller.start<nfd::RibRegisterCommand>(
    parameters,
    [this, caPrefix] (const ControlParameters&) {
      std::cout << "\nGetting certificate from CA " << caPrefix << "\n";

      try {
        const std::string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890";
        std::string randomUserIdentity;
        std::generate_n(std::back_inserter(randomUserIdentity), 10,
                        [&letters] () -> char {
                          return letters[random::generateSecureWord32() % letters.size()];
                        });
        std::cerr << "GEN IDENTITY: '" << randomUserIdentity << "'" << std::endl;

        BOOST_ASSERT(m_ndncertTool != nullptr);
        m_ndncertTool->start(randomUserIdentity);
      }
      catch (const std::exception& error) {
        std::cerr << boost::diagnostic_information(error) << std::endl;
        this->retval = -1;
        this->errorInfo = error.what();
      }
    },
    [this] (const ControlResponse& resp) {
      std::cerr << "Error " << resp.getCode() << " when registering CA prefix. Cannot proceed";
      this->retval = -1;
      this->errorInfo = "Error when registering CA prefix. Cannot proceed";
    });
}

} // namespace autodiscovery
} // namespace ndn


int
main(int argc, char** argv)
{
  ndn::autodiscovery::AutoDiscovery autodisc;
  autodisc.doStart();

  return autodisc.retval;
}
