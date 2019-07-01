/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "location-client-tool.hpp"

#include <unistd.h>
#include <iostream>
#include <string>

#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {

LocationClientTool::LocationClientTool(Face& face, KeyChain& keyChain, const Name& caPrefix, const Certificate& caCert)
  : client(face, keyChain)
{
  std::ostringstream os;
  ndn::io::save(caCert, os);

  std::string dummyConfig = R"STR(
    {
      "ca-list":
      [
        {
            "ca-prefix": )STR" + caPrefix.toUri() + R"STR(/CA,
            "ca-info": "",
            "probe": "will do probing",
            "certificate": ")STR" + os.str() +  R"STR("
        }
      ],
      "local-ndncert-anchor": "not-used"
    }
  )STR";

  std::cerr << "Generated config: " << dummyConfig << std::endl;
  std::istringstream input(dummyConfig);
  JsonSection config;
  boost::property_tree::read_info(input, config);
  client.getClientConf().load(config);
}

void
LocationClientTool::start(const std::string& userIdentity)
{
  ClientCaItem targetCaItem(*(client.getClientConf().m_caItems.begin()));

  // Start with _PROBE
  client.sendProbe(targetCaItem, userIdentity,
                   bind(&LocationClientTool::newCb, this, _1),
                   bind(&LocationClientTool::errorCb, this, _1));
}

void
LocationClientTool::errorCb(const std::string& errorInfo)
{
  std::cerr << "Error: " << errorInfo << std::endl;
}

void
LocationClientTool::newCb(const shared_ptr<RequestState>& state)
{
  state->challenge = ChallengeModule::createChallengeModule("LOCATION_CHALLENGE");

  client.sendSelect(state, LOCATION_CHALLENGE, state->challenge->genSelectParamsJson(state->m_status, {}),
                    [this] (const shared_ptr<RequestState>& state) {
                      selectCb(state);
                    },
                    bind(&LocationClientTool::errorCb, this, _1));
}

void
LocationClientTool::selectCb(const shared_ptr<RequestState>& state)
{
  client.sendValidate(state, state->challenge->genValidateParamsJson(state->m_status, {"000000"}),
                      [] (const shared_ptr<RequestState>& state) {
                        std::cerr << "Got callback from SELECT command" << std::endl;
                      },
                      // bind(&LocationClientTool::validateCb, this, _1),
                      bind(&LocationClientTool::errorCb, this, _1));
  return;
}

void
LocationClientTool::downloadCb(const shared_ptr<RequestState>& state)
{
  std::cerr << " DONE! Certificate has already been installed to local keychain\n";
  return;
}

void
LocationClientTool::validateCb(const shared_ptr<RequestState>& state)
{
  // if (state->m_challengeType == "LOCATION") {
  //   std::cerr << "DONE! Certificate has already been issued \n";

  //   client.requestDownload(state,
  //                          bind(&LocationClientTool::downloadCb, this, _1),
  //                          bind(&LocationClientTool::errorCb, this, _1));
  //   return;
  // }

  // if (state->m_status == ChallengeModule::SUCCESS) {
  //   std::cerr << "DONE! Certificate has already been issued \n";
  //   client.requestDownload(state,
  //                          bind(&LocationClientTool::downloadCb, this, _1),
  //                          bind(&LocationClientTool::errorCb, this, _1));
  //   return;
  // }

  // auto challenge = ChallengeModule::createChallengeModule(state->m_challengeType);
  // auto requirementList = challenge->getRequirementForValidate(state->m_status);

  // auto paramJson = challenge->genValidateParamsJson(state->m_status, paraList);
  // client.sendValidate(state, paramJson,
  //                     bind(&LocationClientTool::validateCb, this, _1),
  //                     bind(&LocationClientTool::errorCb, this, _1));
}

} // namespace ndncert
} // namespace ndn
