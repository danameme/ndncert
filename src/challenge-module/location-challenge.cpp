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
#include "logging.hpp"
#include "json-helper.hpp"

#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.location-challenge);

NDNCERT_REGISTER_CHALLENGE(LocationChallenge, "LOCATION");

const std::string LocationChallenge::NEED_CODE = "need-code";
const std::string LocationChallenge::WRONG_CODE = "wrong-code";

const std::string LocationChallenge::FAILURE_TIMEOUT = "failure-timeout";

const std::string LocationChallenge::JSON_CODE_TP = "code-timepoint";
const std::string LocationChallenge::JSON_PIN_CODE = "code";

LocationChallenge::LocationChallenge()
  : ChallengeModule("LOCATION")
{
}

JsonSection
LocationChallenge::processSelectInterest(const Interest& interest, CertificateRequest& request)
{
  namespace t = ndn::security::transform;

  // interest format: /caName/CA/_SELECT/{"request-id":"id"}/LOCATION/<signature>
  request.setStatus(NEED_CODE);
  request.setChallengeType(CHALLENGE_TYPE);
  std::string secretCode = generateSecretCode();
  request.setChallengeSecrets(generateStoredSecrets(time::system_clock::now(), secretCode));
  _LOG_TRACE("Secret for request " << request.getRequestId() << " : " << secretCode);

  // encrypt
  t::PublicKey key;
  key.loadPkcs8(request.getCert().getPublicKey().data(), request.getCert().getPublicKey().size());
  auto block = key.encrypt(reinterpret_cast<const uint8_t*>(secretCode.data()), secretCode.size());

  // base64 encode
  std::ostringstream os;
  t::bufferSource(block->data(), block->size()) >> t::base64Encode() >> t::stripSpace("\n") >> t::streamSink(os);

  return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, NEED_CODE, {},
                                  {{"code1", os.str()}});
}

JsonSection
LocationChallenge::processValidateInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_VALIDATION/{"request-id":"id"}/LOCATION/{"code":"code"}/<signature>
  JsonSection infoJson = getJsonFromNameComponent(interest.getName(), request.getCaName().size() + 4);
  std::string givenCode = infoJson.get<std::string>(JSON_PIN_CODE);

  const auto parsedSecret = parseStoredSecrets(request.getChallengeSecrets());
  if (time::system_clock::now() - std::get<0>(parsedSecret) >= m_secretLifetime) {
    // secret expires
    request.setStatus(FAILURE_TIMEOUT);
    request.setChallengeSecrets(JsonSection());
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_TIMEOUT);
  }
  else if (givenCode == std::get<1>(parsedSecret)) {
    request.setStatus(SUCCESS);
    request.setChallengeSecrets(JsonSection());
    Name downloadName = genDownloadName(request.getCaName(), request.getRequestId());
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, SUCCESS, downloadName);
  }
  else {
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, WRONG_CODE);
  }
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
  result.put(JSON_PIN_CODE, paramList.front());
  return result;
}

std::tuple<time::system_clock::TimePoint, std::string>
LocationChallenge::parseStoredSecrets(const JsonSection& storedSecrets)
{
  auto tp = time::fromIsoString(storedSecrets.get<std::string>(JSON_CODE_TP));
  std::string rightCode = storedSecrets.get<std::string>(JSON_PIN_CODE);

  return std::make_tuple(tp, rightCode);
}

JsonSection
LocationChallenge::generateStoredSecrets(const time::system_clock::TimePoint& tp, const std::string& secretCode)
{
  JsonSection json;
  json.put(JSON_CODE_TP, time::toIsoString(tp));
  json.put(JSON_PIN_CODE, secretCode);
  return json;
}


} // namespace ndncert
} // namespace ndn
