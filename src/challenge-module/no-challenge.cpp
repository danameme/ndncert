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

#include "no-challenge.hpp"
#include "logging.hpp"
#include "json-helper.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.no-challenge);

NDNCERT_REGISTER_CHALLENGE(NoChallenge, "NOCHALL");


const std::string NoChallenge::NO_CODE = "no-code";
const std::string NoChallenge::WRONG_CODE = "wrong-code";

const std::string NoChallenge::FAILURE_TIMEOUT = "failure-timeout";
const std::string NoChallenge::FAILURE_MAXRETRY = "failure-max-retry";

const std::string NoChallenge::JSON_CODE_TP = "code-timepoint";
const std::string NoChallenge::JSON_PIN_CODE = "code";
const std::string NoChallenge::JSON_ATTEMPT_TIMES = "attempt-times";



NoChallenge::NoChallenge()
  : ChallengeModule("NOCHALL")
{
}

JsonSection
NoChallenge::processSelectInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_SELECT/{"request-id":"id"}/PIN/<signature>
  request.setStatus(NO_CODE);
  request.setChallengeType(CHALLENGE_TYPE);
  std::string secretCode = generateSecretCode();
  request.setChallengeSecrets(generateStoredSecrets(time::system_clock::now(),
                                                    secretCode,
                                                    m_maxAttemptTimes));
  _LOG_TRACE("Secret for request " << request.getRequestId() << " : " << secretCode);
  return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, NO_CODE);
}

JsonSection
NoChallenge::processValidateInterest(const Interest& interest, CertificateRequest& request)
{
    //---Validate certificate without any challenge-reponse
    request.setStatus(SUCCESS);
    request.setChallengeSecrets(JsonSection());
    Name downloadName = genDownloadName(request.getCaName(), request.getRequestId());
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, SUCCESS, downloadName);
}

std::list<std::string>
NoChallenge::getSelectRequirements()
{
  std::list<std::string> result;
  return result;
}

std::list<std::string>
NoChallenge::getValidateRequirements(const std::string& status)
{
  std::list<std::string> result;
  if (status == NO_CODE) {
    result.push_back("Verification code by-passed:");
  }
  else if (status == WRONG_CODE) {
    result.push_back("Incorrect PIN code, please try again and input your verification code:");
  }
  return result;
}

JsonSection
NoChallenge::doGenSelectParamsJson(const std::string& status,
                                    const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(status == WAIT_SELECTION);
  BOOST_ASSERT(paramList.size() == 0);
  return result;
}

JsonSection
NoChallenge::doGenValidateParamsJson(const std::string& status,
                                      const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(paramList.size() == 1);
  result.put(JSON_PIN_CODE, paramList.front());
  return result;
}

std::tuple<time::system_clock::TimePoint, std::string, int>
NoChallenge::parseStoredSecrets(const JsonSection& storedSecrets)
{
  auto tp = time::fromIsoString(storedSecrets.get<std::string>(JSON_CODE_TP));
  std::string rightCode= storedSecrets.get<std::string>(JSON_PIN_CODE);
  int attemptTimes = std::stoi(storedSecrets.get<std::string>(JSON_ATTEMPT_TIMES));

  return std::make_tuple(tp, rightCode, attemptTimes);
}

JsonSection
NoChallenge::generateStoredSecrets(const time::system_clock::TimePoint& tp,
                                    const std::string& secretCode, int attempTimes)
{
  JsonSection json;
  json.put(JSON_CODE_TP, time::toIsoString(tp));
  json.put(JSON_PIN_CODE, secretCode);
  json.put(JSON_ATTEMPT_TIMES, std::to_string(attempTimes));
  return json;
}


} // namespace ndncert
} // namespace ndn
