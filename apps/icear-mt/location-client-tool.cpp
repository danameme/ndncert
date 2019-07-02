/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "location-client-tool.hpp"

#include <unistd.h>
#include <iostream>
#include <string>

#include <ndn-cxx/security/transform.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>

#include <boost/exception/diagnostic_information.hpp>

namespace ndn {
namespace ndncert {

LocationClientTool::LocationClientTool(Face& face, KeyChain& keyChain, const Name& caPrefix, const Certificate& caCert)
  : client(face, keyChain)
  , m_keyChain(keyChain)
{
  namespace t = ndn::security::transform;
  std::ostringstream os;
  t::bufferSource(caCert.wireEncode().wire(), caCert.wireEncode().size())
    >> t::base64Encode()
    >> t::stripSpace("\n")
    >> t::streamSink(os);

  std::string dummyConfig = R"STR(
    {
      "ca-list":
      [
        {
            "ca-prefix": ")STR" + caPrefix.toUri() + R"STR(/CA",
            "ca-info": "",
            "probe": "will do probing",
            "certificate": ")STR" + os.str() +  R"STR("
        }
      ],
      "local-ndncert-anchor": ")STR" + os.str() +  R"STR("
    }
  )STR";

  std::cerr << "Generated config: " << dummyConfig << std::endl;
  std::istringstream input(dummyConfig);
  JsonSection config;
  try {
    boost::property_tree::read_json(input, config);
    client.getClientConf().load(config);
  }
  catch (const std::exception& error) {
    std::cerr << boost::diagnostic_information(error) << std::endl;
    throw;
  }
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
  state->challenge = ChallengeModule::createChallengeModule(LOCATION_CHALLENGE);
  BOOST_ASSERT(state->challenge != nullptr);

  client.sendSelect(state, LOCATION_CHALLENGE, state->challenge->genSelectParamsJson(state->m_status, {}),
                    [this] (const shared_ptr<RequestState>& state) {
                      selectCb(state);
                    },
                    bind(&LocationClientTool::errorCb, this, _1));
}

void
LocationClientTool::selectCb(const shared_ptr<RequestState>& state)
{
  namespace t = ndn::security::transform;

  // decode what needs to be decoded
  auto code1 = state->challengeData.find("code1");
  if (code1 == state->challengeData.end()) {
    std::cerr << "ERROR: the _SELECT/LOCATION response didn't include expected `code1` field" << std::endl;
    return;
  }

  // decode base64
  std::istringstream is(code1->second);
  OBufferStream os;
  t::streamSource(is) >> t::stripSpace("\n") >> t::base64Decode(false) >> t::streamSink(os);
  // decrypt
  auto codeBuffer = m_keyChain.getTpm().decrypt(os.buf()->data(), os.buf()->size(), state->m_key.getName());

  // convert to unencrypted code string and store in the client state
  code1->second = std::string(reinterpret_cast<const char*>(codeBuffer->data()), codeBuffer->size());

  // !! the code will be sent in clear text !! (at least for now)
  client.sendValidate(state, state->challenge->genValidateParamsJson(state->m_status, {code1->second}),
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
