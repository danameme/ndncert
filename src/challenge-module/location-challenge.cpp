/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "location-challenge.hpp"
#include "json-helper.hpp"
#include "logging.hpp"
#include "ca-module.hpp"

#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.LocationChallenge);

NDNCERT_REGISTER_CHALLENGE(LocationChallenge, "LOCATION");

const std::string LocationChallenge::NEED_CODE = "need-code";
const std::string LocationChallenge::WRONG_CODE = "wrong-code";

const std::string LocationChallenge::FAILURE_TIMEOUT = "failure-timeout";

const std::string LocationChallenge::JSON_CODE_TP = "code-timepoint";
const std::string LocationChallenge::JSON_PIN_CODE1 = "code1";
const std::string LocationChallenge::JSON_PIN_CODE2 = "code2";

const Name LocationChallenge::LOCALHOP_VALIDATION_PREFIX = "/localhop/CA/VALIDATE";
const Name FAKE_NAME = "/localhop"; // must be 2 components shorter than the validation prefix (kind of hack)

LocationChallenge::LocationChallenge()
  : ChallengeModule("LOCATION")
{
}

void
LocationChallenge::doRegisterChallengeActions(Face& face, KeyChain& keyChain, const PrevalidateCallback& prevalidate)
{
  m_face = &face;
  m_keyChain = &keyChain;

  m_localhopRegistration = m_face->setInterestFilter(LOCALHOP_VALIDATION_PREFIX,
                                                     [this, prevalidate] (const auto&, const Interest &interest) {
                                                       auto request = prevalidate(interest, FAKE_NAME);
                                                       if (request.isEmpty()) {
                                                         return;
                                                       }
                                                       auto content = this->processLocalhopInterest(interest, request);

                                                       Data result;
                                                       result.setName(interest.getName());
                                                       result.setContent(CaModule::dataContentFromJson(content));
                                                       m_keyChain->sign(result, signingByIdentity(request.getCaName()));
                                                       m_face->put(result);
                                                     },
                                                     [] (const auto&...) {});
}

static std::string
encryptAndBase64(const Buffer& publicKey, const std::string& toEncrypt)
{
  namespace t = ndn::security::transform;

  // encrypt
  t::PublicKey key;
  key.loadPkcs8(publicKey.data(), publicKey.size());
  auto block = key.encrypt(reinterpret_cast<const uint8_t*>(toEncrypt.data()), toEncrypt.size());

  // base64 encode
  std::ostringstream os;
  t::bufferSource(block->data(), block->size()) >> t::base64Encode() >> t::stripSpace("\n") >> t::streamSink(os);
  return os.str();
}


JsonSection
LocationChallenge::processSelectInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_SELECT/{"request-id":"id"}/LOCATION/<signature>
  request.setStatus(NEED_CODE);
  request.setChallengeType(CHALLENGE_TYPE);
  std::string secretCode1 = generateSecretCode(32, false);
  std::string secretCode2 = generateSecretCode(32, false);

  request.setChallengeSecrets(generateStoredSecrets(time::system_clock::now(), secretCode1, secretCode2));

  return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, NEED_CODE, {},
                                  {{"code1", encryptAndBase64(request.getCert().getPublicKey(), secretCode1)}});
}

JsonSection
LocationChallenge::processValidateInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_VALIDATION/{"request-id":"id"}/LOCATION/{"code":"code"}/<signature>
  JsonSection infoJson = getJsonFromNameComponent(interest.getName(), request.getCaName().size() + 4);
  std::string givenCode = infoJson.get<std::string>(JSON_PIN_CODE2);

  const auto parsedSecret = parseStoredSecrets(request.getChallengeSecrets());
  if (time::system_clock::now() - std::get<0>(parsedSecret) >= m_secretLifetime) {
    // secret expires
    request.setStatus(FAILURE_TIMEOUT);
    request.setChallengeSecrets(JsonSection());
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_TIMEOUT);
  }
  else if (givenCode == std::get<2>(parsedSecret)) { // secret code 2 (obtainable if /localhop validation succeeds)
    request.setStatus(SUCCESS);
    request.setChallengeSecrets(JsonSection());
    Name downloadName = genDownloadName(request.getCaName(), request.getRequestId());
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, SUCCESS, downloadName);
  }
  else {
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, WRONG_CODE);
  }
}

JsonSection
LocationChallenge::processLocalhopInterest(const Interest& interest, CertificateRequest& request)
{
  _LOG_DEBUG("processLocalhopInterest");
  // interest format: /localhop/CA/VALIDATE/{"request-id":"id"}/LOCATION/{"code":"code"}/<signature>
  JsonSection infoJson = getJsonFromNameComponent(interest.getName(), 5);
  std::string givenCode = infoJson.get<std::string>(JSON_PIN_CODE1);

  const auto parsedSecret = parseStoredSecrets(request.getChallengeSecrets());
  _LOG_DEBUG("after secrets");
  if (time::system_clock::now() - std::get<0>(parsedSecret) >= m_secretLifetime) {
    _LOG_DEBUG("code expired");
    // secret expires
    request.setStatus(FAILURE_TIMEOUT);
    request.setChallengeSecrets(JsonSection());
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_TIMEOUT);
  }
  else if (givenCode == std::get<1>(parsedSecret)) { // secret code 1
    _LOG_DEBUG("code matches");
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, NEED_CODE, {},
                                    {{"code2", encryptAndBase64(request.getCert().getPublicKey(), std::get<2>(parsedSecret))}});
  }
  else {
    _LOG_DEBUG("code doesn't match");
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, WRONG_CODE);
  }

  return {};
}

JsonSection
LocationChallenge::genLocalhopParamsJson(const std::string& status, const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(paramList.size() == 1);
  result.put(JSON_PIN_CODE1, paramList.front());
  return result;
}

std::list<std::string>
LocationChallenge::getSelectRequirements()
{
  std::list<std::string> result;
  return result;
}

std::list<std::string>
LocationChallenge::getValidateRequirements(const std::string& status)
{
  return {};
}

JsonSection
LocationChallenge::doGenSelectParamsJson(const std::string& status,
                                         const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(status == WAIT_SELECTION);
  BOOST_ASSERT(paramList.size() == 0);
  return result;
}

JsonSection
LocationChallenge::doGenValidateParamsJson(const std::string& status,
                                           const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(paramList.size() == 1);
  result.put(JSON_PIN_CODE2, paramList.front());
  return result;
}

std::tuple<time::system_clock::TimePoint, std::string, std::string>
LocationChallenge::parseStoredSecrets(const JsonSection& storedSecrets)
{
  return {
      time::fromIsoString(storedSecrets.get<std::string>(JSON_CODE_TP)),
      storedSecrets.get<std::string>(JSON_PIN_CODE1),
      storedSecrets.get<std::string>(JSON_PIN_CODE2)
    };
}

JsonSection
LocationChallenge::generateStoredSecrets(const time::system_clock::TimePoint& tp,
                                         const std::string& secretCode1, const std::string& secretCode2)
{
  JsonSection json;
  json.put(JSON_CODE_TP, time::toIsoString(tp));
  json.put(JSON_PIN_CODE1, secretCode1);
  json.put(JSON_PIN_CODE2, secretCode2);
  return json;
}


} // namespace ndncert
} // namespace ndn
