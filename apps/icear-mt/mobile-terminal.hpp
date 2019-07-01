/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP
#define NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/net/face-uri.hpp>

#include "location-client-tool.hpp"

namespace ndn {
namespace autodiscovery {

class AutoDiscovery
{
public:
  AutoDiscovery();

  void
  doStart();

  void
  registerHubDiscoveryPrefix(const std::vector<nfd::FaceStatus>& dataset);

  void
  afterReg();

  void
  setStrategy();

  void
  onInterest(const InterestFilter& filter, const Interest& interest);

  void
  startListener();

  void
  onRegisterFailed(const Name& prefix, const std::string& reason);

  void
  requestHubData(size_t nRetriesLeft);

  void
  fail(const std::string& msg);

  void
  succeed(const FaceUri& hubFaceUri);

  void
  registerPrefixAndRunNdncert(const Name& caPrefix, uint64_t faceId);

public:
  int retval = 0;
  std::string errorInfo = "";

private:
  Face m_face;
  KeyChain m_keyChain;
  nfd::Controller m_controller;
  Scheduler m_scheduler;
  std::unique_ptr<ndncert::LocationClientTool> m_ndncertTool;

  int m_nRegs = 0;
  int m_nRegSuccess = 0;
  int m_nRegFailure = 0;
};

} // namespace autodiscovery
} // namespace ndn

#endif // NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP
