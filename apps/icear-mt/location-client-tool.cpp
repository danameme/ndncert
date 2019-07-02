/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "location-client-tool.hpp"
#include "challenge-module/location-challenge.hpp"
#include "logging.hpp"

#include <unistd.h>
#include <iostream>
#include <string>

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

#include <boost/exception/diagnostic_information.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.LocationClientTool);

LocationClientTool::LocationClientTool(Face& face, KeyChain& keyChain, const Name& caPrefix, const Certificate& caCert)
  : client(face, keyChain)
  , m_keyChain(keyChain)
  , m_face(face)
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

static std::string
base64DecodeAndDecrypt(const std::string& encrypted, KeyChain& keyChain, const Name& keyName)
{
  namespace t = ndn::security::transform;

  // decode base64
  std::istringstream is(encrypted);
  OBufferStream os;
  t::streamSource(is) >> t::stripSpace("\n") >> t::base64Decode(false) >> t::streamSink(os);
  // decrypt
  auto codeBuffer = keyChain.getTpm().decrypt(os.buf()->data(), os.buf()->size(), keyName);

  // convert to unencrypted code string and store in the client state
  return std::string(reinterpret_cast<const char*>(codeBuffer->data()), codeBuffer->size());
}

void
LocationClientTool::selectCb(const shared_ptr<RequestState>& state)
{
  // decode what needs to be decoded
  auto code1 = state->challengeData.find("code1");
  if (code1 == state->challengeData.end()) {
    std::cerr << "ERROR: the _SELECT/LOCATION response didn't include expected `code1` field" << std::endl;
    return;
  }

  code1->second = base64DecodeAndDecrypt(code1->second, m_keyChain, state->m_key.getName());

  // !! the code will be sent in clear text !! (at least for now)
  sendLocalhopValidate(state, static_cast<LocationChallenge*>(state->challenge.get())->genLocalhopParamsJson(state->m_status, {code1->second}),
                      [this] (const shared_ptr<RequestState>& state) {
                        localhopValidateCb(state);
                      },
                      bind(&LocationClientTool::errorCb, this, _1));
}

void
LocationClientTool::sendLocalhopValidate(const shared_ptr<RequestState>& state,
                                         const JsonSection& validateParams,
                                         const ClientModule::RequestCallback& requestCallback,
                                         const ClientModule::ErrorCallback& errorCallback)
{
  JsonSection requestIdJson;
  requestIdJson.put(JSON_REQUEST_ID, state->m_requestId);
  std::string challType = state->m_challengeType;

  Name interestName(LocationChallenge::LOCALHOP_VALIDATION_PREFIX);
  interestName
    .append(ClientModule::nameBlockFromJson(requestIdJson))
    .append(state->m_challengeType)
    .append(ClientModule::nameBlockFromJson(validateParams));
  Interest interest(interestName);
  interest.setCanBePrefix(false);
  m_keyChain.sign(interest, signingByKey(state->m_key.getName()));

  DataCallback dataCb = bind(&LocationClientTool::handleLocalhopValidateResponse,
                             this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, &client, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, &client, _1, 3,
                              dataCb, errorCallback));

  _LOG_TRACE(LocationChallenge::LOCALHOP_VALIDATION_PREFIX << " interest sent");
}

void
LocationClientTool::handleLocalhopValidateResponse(const Interest& request,
                                                   const Data& reply,
                                                   const shared_ptr<RequestState>& state,
                                                   const ClientModule::RequestCallback& requestCallback,
                                                   const ClientModule::ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }
  //gotMessage = reply.getName()[-1].toUri();
  JsonSection json = ClientModule::getJsonFromData(reply);
  state->m_status = json.get<std::string>(JSON_STATUS);

  auto challengeData = json.get_child_optional(JSON_CHALLENGE_DATA);
  if (challengeData) {
    for (const auto& item : *challengeData) {
      // this may throw if there are unexpected items inside returned challenge-data
      state->challengeData[item.first] = item.second.get_value<std::string>();
    }
  }

  if (!ClientModule::checkStatus(*state, json, errorCallback)) {
    return;
  }

  _LOG_TRACE("Got " << LocationChallenge::LOCALHOP_VALIDATION_PREFIX << " response with status " << state->m_status);

  requestCallback(state);
}

void
LocationClientTool::localhopValidateCb(const shared_ptr<RequestState>& state)
{
  // decode what needs to be decoded
  auto code2 = state->challengeData.find("code2");
  if (code2 == state->challengeData.end()) {
    std::cerr << "ERROR: the _SELECT/LOCATION response didn't include expected `code2` field" << std::endl;
    return;
  }

  code2->second = base64DecodeAndDecrypt(code2->second, m_keyChain, state->m_key.getName());

  // !! the code will be sent in clear text !! (at least for now)
  client.sendValidate(state, state->challenge->genValidateParamsJson(state->m_status, {code2->second}),
                      [this] (const shared_ptr<RequestState>& state) {
                        validateCb(state);
                      },
                      bind(&LocationClientTool::errorCb, this, _1));
}

void
LocationClientTool::validateCb(const shared_ptr<RequestState>& state)
{
  if (state->m_status == ChallengeModule::SUCCESS) {
    std::cerr << "DONE! Certificate has already been issued \n";
    client.requestDownload(state,
                           bind(&LocationClientTool::downloadCb, this, _1),
                           bind(&LocationClientTool::errorCb, this, _1));
    return;
  }
}

void
LocationClientTool::downloadCb(const shared_ptr<RequestState>& state)
{
  std::cerr << " DONE! Certificate has already been installed to local keychain\n";
  return;
}

} // namespace ndncert
} // namespace ndn
