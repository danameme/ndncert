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

#ifndef NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP
#define NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/net/face-uri.hpp>

/*
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/security/key-chain.hpp>
*/

namespace ndn {
namespace autodiscovery {

/** \brief multicast discovery stage
 *
 *  This stage locates an NDN gateway router, commonly known as a "hub", in the local network by
 *  sending a hub discovery Interest ndn:/localhop/ndn-autoconf/hub via multicast. This class
 *  configures routes and strategy on local NFD, so that this Interest is multicast to all
 *  multi-access faces.
 *
 *  If an NDN gateway router is present in the local network, it should reply with a Data
 *  containing its own FaceUri. The Data payload contains a Uri element, and the value of this
 *  element is an ASCII-encoded string of the router's FaceUri. The router may use
 *  ndn-autoconfig-server program to serve this Data.
 *
 *  Signature on this Data is currently not verified. This stage succeeds when the Data is
 *  successfully decoded.
 */
class AutoDiscovery
{
public:
  AutoDiscovery(Face& face, nfd::Controller& controller);

  void 
  RunNdncert();

  const std::string&
  getName()
  {
    static const std::string STAGE_NAME("multicast discovery");
    return STAGE_NAME;
  }

  static std::string m_CERT_NAMESPACE;

   /** \brief signal when a HUB FaceUri is found
   *
   *  Argument is HUB FaceUri, may not be canonical.
   */
  util::Signal<AutoDiscovery, FaceUri> onSuccess;

   /** \brief signal when discovery fails
   *
   *  Argument is error message.
   */
  util::Signal<AutoDiscovery, std::string> onFailure;

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
  requestHubData();

  void
  fail(const std::string& msg);

  void
  succeed(const FaceUri& hubFaceUri);

  /** \brief parse HUB FaceUri from string and declare success
   */
  void
  provideHubFaceUri(const std::string& s);

private:
  Face& m_face;
  nfd::Controller& m_controller;

  int m_nRegs = 0;
  int m_nRegSuccess = 0;
  int m_nRegFailure = 0;

};

} // namespace autodiscovery
} // namespace ndn

#endif // NFD_TOOLS_NDN_AUTOCONFIG_MULTICAST_DISCOVERY_HPP
