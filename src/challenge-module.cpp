/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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

#include "challenge-module.hpp"
#include "logging.hpp"

#include <ndn-cxx/util/random.hpp>

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.challenge-module);

const std::string ChallengeModule::WAIT_SELECTION = "wait-selection";
const std::string ChallengeModule::SUCCESS = "success";
const std::string ChallengeModule::PENDING = "pending";
const std::string ChallengeModule::FAILURE = "failure";

ChallengeModule::ChallengeModule(const std::string& uniqueType)
  : CHALLENGE_TYPE(uniqueType)
{
}

ChallengeModule::~ChallengeModule() = default;

unique_ptr<ChallengeModule>
ChallengeModule::createChallengeModule(const std::string& canonicalName)
{
  ChallengeFactory& factory = getFactory();
  auto i = factory.find(canonicalName);
  return i == factory.end() ? nullptr : i->second();
}

JsonSection
ChallengeModule::handleChallengeRequest(const Interest& interest, CertificateRequest& request)
{
  int pos = request.getCaName().size() + 1;
  const Name& interestName = interest.getName();
  std::string interestType = interestName.get(pos).toUri();

  _LOG_TRACE("Incoming challenge request. type: " << interestType);

  if (interestType == "_SELECT") {
    return processSelectInterest(interest, request);
  }
  else if (interestType == "_VALIDATE"){
    return processValidateInterest(interest, request);
  }
  else {
    return processStatusInterest(interest, request);
  }
}

std::list<std::string>
ChallengeModule::getRequirementForSelect()
{
  return getSelectRequirements();
}

std::list<std::string>
ChallengeModule::getRequirementForValidate(const std::string& status)
{
  return getValidateRequirements(status);
}

JsonSection
ChallengeModule::genSelectParamsJson(const std::string& status,
                                     const std::list<std::string>& paramList)
{
  return doGenSelectParamsJson(status, paramList);
}

JsonSection
ChallengeModule::genValidateParamsJson(const std::string& status,
                                     const std::list<std::string>& paramList)
{
  return doGenValidateParamsJson(status, paramList);
}

void
ChallengeModule::registerChallengeActions(Face& face, KeyChain& keyChain, const PrevalidateCallback& prevalidate)
{
  return doRegisterChallengeActions(face, keyChain, prevalidate);
}

void
ChallengeModule::doRegisterChallengeActions(Face& face, KeyChain& keyChain, const PrevalidateCallback& prevalidate)
{
  // do nothing by default
}

JsonSection
ChallengeModule::processStatusInterest(const Interest& interest, const CertificateRequest& request)
{
  // interest format: /CA/_STATUS/{"request-id":"id"}/<signature>
  if (request.getStatus() == SUCCESS) {
    Name downloadName = genDownloadName(request.getCaName(), request.getStatus());
    return genResponseChallengeJson(request.getRequestId(), request.getChallengeType(),
                                    SUCCESS, downloadName);
  }
  else
    return genResponseChallengeJson(request.getRequestId(), request.getChallengeType(),
                                    request.getStatus());
}

JsonSection
ChallengeModule::getJsonFromNameComponent(const Name& name, int pos)
{
  std::string jsonString = encoding::readString(name.get(pos));
  std::istringstream ss(jsonString);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

Name
ChallengeModule::genDownloadName(const Name& caName, const std::string& requestId)
{
  JsonSection json;
  json.put(JSON_REQUEST_ID, requestId);
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  Block jsonBlock = makeStringBlock(ndn::tlv::GenericNameComponent, ss.str());
  Name name = caName;
  name.append("_DOWNLOAD").append(jsonBlock);
  return name;
}

std::list<std::string>
ChallengeModule::getRegisteredChallenges()
{
  std::list<std::string> retval;
  boost::copy(getFactory() | boost::adaptors::map_keys, std::back_inserter(retval));
  return retval;
}

ChallengeModule::ChallengeFactory&
ChallengeModule::getFactory()
{
  static ChallengeModule::ChallengeFactory factory;
  return factory;
}

std::string
ChallengeModule::generateSecretCode(size_t length, bool onlyDigits)
{
  const std::string DIGITS = "0123456789";
  const std::string ALPHABET = "abcdeifhijklmnopqrstuvwxyzABCDEIFHIJKLMNOPQRSTUVWXYZ0123456789";

  std::ostringstream os;
  while (length > 0) {
    uint32_t securityCode = random::generateSecureWord32();
    for (size_t i = 0; i < 4 && length > 0; i++) {
      uint8_t randByte = securityCode & 0xFF;
      securityCode >>= 8;

      // using module is really wrong (the distribution is not uniform), but don't really care here...
      if (onlyDigits) {
        os << DIGITS[randByte % DIGITS.size()];
      }
      else {
        os << ALPHABET[randByte % ALPHABET.size()];
      }
      --length;
    }
  }
  return os.str();
}

} // namespace ndncert
} // namespace ndn
