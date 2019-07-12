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

#include "ca-module.hpp"
#include "logging.hpp"

#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ca);

CaModule::CaModule(Face& face, security::v2::KeyChain& keyChain,
                   const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CaStorage::createCaStorage(storageType);

  registerPrefix();
}

CaModule::~CaModule()
{
}

void
CaModule::registerPrefix()
{
  // register localhost list prefix
  Name localProbePrefix("/localhost/CA/_LIST");
  auto prefixId = m_face.setInterestFilter(InterestFilter(localProbePrefix),
                                           bind(&CaModule::handleLocalhostList, this, _2),
                                           bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixIds.push_back(prefixId);

  NDN_LOG_INFO("Prefix " << localProbePrefix << " got registered");

  // register prefixes for each CA
  for (const auto& item : m_config.m_caItems) {
    Name prefix = item.m_caName;
    prefix.append("CA");

    prefixId = m_face.registerPrefix(prefix,
      [&] (const Name& name) {
        // NEW
        auto filterId = m_face.setInterestFilter(Name(name).append("_NEW"),
                                                 bind(&CaModule::handleNew, this, _2, item));
        m_interestFilterIds.push_back(filterId);
        // SELECT
        filterId = m_face.setInterestFilter(Name(name).append("_SELECT"),
                                            bind(&CaModule::handleSelect, this, _2, item));
        m_interestFilterIds.push_back(filterId);
        // VALIDATE
        filterId = m_face.setInterestFilter(Name(name).append("_VALIDATE"),
                                            bind(&CaModule::handleValidate, this, _2, item));
        m_interestFilterIds.push_back(filterId);
        // STATUS
        filterId = m_face.setInterestFilter(Name(name).append("_STATUS"),
                                            bind(&CaModule::handleStatus, this, _2, item));
        m_interestFilterIds.push_back(filterId);
        // DOWNLOAD
        filterId = m_face.setInterestFilter(Name(name).append("_DOWNLOAD"),
                                            bind(&CaModule::handleDownload, this, _2, item));
        m_interestFilterIds.push_back(filterId);
        // PROBE
        if (item.m_probe != "") {
          filterId = m_face.setInterestFilter(Name(name).append("_PROBE"),
                                              bind(&CaModule::handleProbe, this, _2, item));
          m_interestFilterIds.push_back(filterId);
        }
        // LIST
        if (item.m_relatedCaList.size() > 0) {
          filterId = m_face.setInterestFilter(Name(name).append("_LIST"),
                                              bind(&CaModule::handleList, this, _2, item));
          m_interestFilterIds.push_back(filterId);
        }

	NDN_LOG_INFO("Prefix " << name << " got registered");
      },
      bind(&CaModule::onRegisterFailed, this, _2));
    m_registeredPrefixIds.push_back(prefixId);
  }

  for (const auto& name : ChallengeModule::getRegisteredChallenges()) {
    auto challenge = ChallengeModule::createChallengeModule(name);
    auto item = m_challenges.emplace(name, std::move(challenge));

    item.first->second->registerChallengeActions(m_face, m_keyChain, [this, name] (const Interest& request, const Name& preParamsPrefix) {
        _LOG_TRACE("Handle " << preParamsPrefix << " for challenge " << name);
	
        CertificateRequest certRequest = getCertificateRequest(request, preParamsPrefix);
        if (certRequest.getRequestId().empty()) {
          return certRequest;
        }

        if (!security::verifySignature(request, certRequest.getCert())) {
          _LOG_TRACE("Interest with bad signature.");
          return CertificateRequest();
        }

        return certRequest;
      });
  }
}

bool
CaModule::setProbeHandler(const Name caName, const ProbeHandler& handler)
{
  for (auto& entry : m_config.m_caItems) {
    if (entry.m_caName == caName) {
      entry.m_probeHandler = handler;
      return true;
    }
  }
  return false;
}

bool
CaModule::setRecommendCaHandler(const Name caName, const RecommendCaHandler& handler)
{
  for (auto& entry : m_config.m_caItems) {
    if (entry.m_caName == caName) {
      entry.m_recommendCaHandler = handler;
      return true;
    }
  }
  return false;
}

bool
CaModule::setStatusUpdateCallback(const Name caName, const StatusUpdateCallback& onUpateCallback)
{
  for (auto& entry : m_config.m_caItems) {
    if (entry.m_caName == caName) {
      entry.m_statusUpdateCallback = onUpateCallback;
      return true;
    }
  }
  return false;
}

void
CaModule::handleLocalhostList(const Interest& request)
{
  _LOG_TRACE("Got Localhost LIST request");

  JsonSection root;
  JsonSection caListSection;

  for (const auto& entry : m_config.m_caItems) {
    JsonSection caItem;

    const auto& pib = m_keyChain.getPib();
    auto identity = pib.getIdentity(entry.m_caName);
    auto cert = identity.getDefaultKey().getDefaultCertificate();

    // ca-prefix
    Name caName = entry.m_caName;
    caName.append("CA");
    caItem.put("ca-prefix", caName.toUri());

    // ca-info
    std::string caInfo;
    if (entry.m_caInfo == "") {
      caInfo = "Issued by " + cert.getSignature().getKeyLocator().getName().toUri();
    }
    else {
      caInfo = entry.m_caInfo;
    }
    caItem.put("ca-info", caInfo);

    // probe is always false for local client

    // ca-target list
    caItem.put("target-list", entry.m_targetedList);

    // certificate
    std::stringstream ss;
    io::save(cert, ss);
    caItem.put("certificate", ss.str());

    caListSection.push_back(std::make_pair("", caItem));
  }
  root.add_child("ca-list", caListSection);

  Data result;
  Name dataName = request.getName();
  dataName.appendTimestamp();
  result.setName(dataName);
  result.setContent(dataContentFromJson(root));
  m_keyChain.sign(result, signingByIdentity(m_keyChain.getPib().getDefaultIdentity().getName()));
  m_face.put(result);
}

void
CaModule::handleList(const Interest& request, const CaItem& caItem)
{
  _LOG_TRACE("Got LIST request");

  bool getRecommendation = false;
  Name recommendedCaName;
  std::string identityName;

  // LIST naming convention: /CA-prefix/CA/_LIST/[optional info]
  if (readString(request.getName().at(-1)) != "_LIST" && caItem.m_recommendCaHandler) {
    const auto& additionInfo = readString(request.getName().at(-1));
    try {
      std::tie(recommendedCaName, identityName) = caItem.m_recommendCaHandler(additionInfo, caItem.m_relatedCaList);
      getRecommendation = true;
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot recommend CA for LIST request. Degrade to non-target list." << e.what());
    }
  }

  JsonSection root;
  JsonSection caListSection;
  if (getRecommendation) {
    // JSON format
    // {
    //   "recommended-ca": "/ndn/edu/ucla"
    //   "recommended-identity": "something"
    //   "trust-schema": "schema Data packet name"
    // }
    root.put("recommended-ca", recommendedCaName.toUri());
    root.put("recommended-identity", identityName);
  }
  else {
    // JSON format
    // {
    //   "ca-list": [
    //     {"ca-prefix": "/ndn/edu/ucla"},
    //     {"ca-prefix": "/ndn/edu/memphis"},
    //     ...
    //   ]
    //   "trust-schema": "schema Data packet name"
    // }
    for (const auto& entry : caItem.m_relatedCaList) {
      JsonSection caItem;
      caItem.put("ca-prefix", entry.toUri());
      caListSection.push_back(std::make_pair("", caItem));
    }
    root.add_child("ca-list", caListSection);
  }

  // TODO: add trust schema
  std::string schemaDataName = "TODO: add trust schema";
  root.put("trust-schema", schemaDataName);

  Data result;
  Name dataName = request.getName();
  dataName.appendTimestamp();
  result.setName(dataName);
  result.setContent(dataContentFromJson(root));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);
}

void
CaModule::handleProbe(const Interest& request, const CaItem& caItem)
{
  // PROBE Naming Convention: /CA-prefix/CA/_PROBE/<Probe Information>

  std::string identifier;
  if (caItem.m_probeHandler) {
    try {
      identifier = caItem.m_probeHandler(readString(request.getName().at(caItem.m_caName.size() + 2)));
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot generate identifier for PROBE request " << e.what());
      return;
    }
  }
  else {
    identifier = readString(request.getName().at(caItem.m_caName.size() + 2));
  }

  NDN_LOG_INFO("<< I: PROBE: request from MT with ID: " << identifier);

  Name identityName = caItem.m_caName;
  identityName.append(identifier);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseProbeJson(identityName, "")));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);


  NDN_LOG_INFO(">> D: PROBE: CA acknowledges if certificate can be issued for requested name " << identityName);
}

void
CaModule::handleNew(const Interest& request, const CaItem& caItem)
{
  // NEW Naming Convention: /CA-prefix/CA/_NEW/<certificate-request>/[signature]

  NDN_LOG_INFO("<< I: NEW: certificate request from MT");

  security::v2::Certificate clientCert;
  try {
    clientCert.wireDecode(request.getName().at(caItem.m_caName.size() + 2).blockFromValue());
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Unrecognized certificate request " << e.what());
    return;
  }

  if (!security::verifySignature(clientCert, clientCert)) {
    _LOG_TRACE("Cert request with bad signature.");
    return;
  }
  if (!security::verifySignature(request, clientCert)) {
    _LOG_TRACE("Interest with bad signature.");
    return;
  }

  std::string requestId = std::to_string(random::generateWord64());
  CertificateRequest certRequest(caItem.m_caName, requestId, clientCert);
  certRequest.setStatus(ChallengeModule::WAIT_SELECTION);
  try {
    m_storage->addRequest(certRequest);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot add new request instance " << e.what());
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseNewJson(requestId, certRequest.getStatus(),
                                                           caItem.m_supportedChallenges)));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  NDN_LOG_INFO(">> D: NEW: CA generates session ID, challenge list and transmit to MT");

  if (caItem.m_statusUpdateCallback) {
    caItem.m_statusUpdateCallback(certRequest);
  }
}

void
CaModule::handleSelect(const Interest& request, const CaItem& caItem)
{
  // SELECT Naming Convention: /CA-prefix/CA/_SELECT/{Request-ID JSON}/<ChallengeID>/
  // {Param JSON}/[Signature components]
  _LOG_TRACE("Handle SELECT request");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Interest with bad signature.");
    return;
  }

  std::string challengeType;
  try {
    challengeType = readString(request.getName().at(caItem.m_caName.size() + 3));
  }
  catch (const std::exception& e) {
    _LOG_ERROR(e.what());
    return;
  }

  NDN_LOG_INFO("<< I: SELECT: request, chooses challenge type " << challengeType);

  auto challenge = m_challenges.find(challengeType);
  if (challenge == m_challenges.end()) {
    _LOG_TRACE("Unrecognized or unsupported challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->second->handleChallengeRequest(request, certRequest);
  if (certRequest.getStatus() == ChallengeModule::FAILURE) {
    m_storage->deleteRequest(certRequest.getRequestId());
  }
  else {
    try {
      m_storage->updateRequest(certRequest);
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot update request instance " << e.what());
      return;
    }
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  NDN_LOG_INFO(">> D: SELECT: CA initializes challenge type " << challengeType << " using RN1");

  if (caItem.m_statusUpdateCallback) {
    caItem.m_statusUpdateCallback(certRequest);
  }
}

void
CaModule::handleValidate(const Interest& request, const CaItem& caItem)
{
  // VALIDATE Naming Convention: /CA-prefix/CA/_VALIDATE/{Request-ID JSON}/<ChallengeID>/
  // {Param JSON}/[Signature components]

  NDN_LOG_INFO("<< I: VALIDATE: request from MT containing RN2 to confirm if challenge is passed");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Interest with bad signature.");
    return;
  }

  std::string challengeType = certRequest.getChallengeType();
  auto challenge = m_challenges.find(challengeType);
  if (challenge == m_challenges.end()) {
    _LOG_TRACE("Unrecognized or unsupported challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->second->handleChallengeRequest(request, certRequest);
  if (certRequest.getStatus() == ChallengeModule::FAILURE) {
    m_storage->deleteRequest(certRequest.getRequestId());
  }
  else {
    try {
      m_storage->updateRequest(certRequest);
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot update request instance " << e.what());
      return;
    }
  }
  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  NDN_LOG_INFO(">> D: VALIDATE: CA sends validation response to MT");

  if (certRequest.getStatus() == ChallengeModule::SUCCESS) {
    auto issuedCert = issueCertificate(certRequest, caItem);
    if (caItem.m_statusUpdateCallback) {
      certRequest.setCert(issuedCert);
      caItem.m_statusUpdateCallback(certRequest);
    }
    try {
      m_storage->addCertificate(certRequest.getRequestId(), issuedCert);
      m_storage->deleteRequest(certRequest.getRequestId());
    }
    catch (const std::exception& e) {
      _LOG_ERROR("Cannot add issued cert and remove the request " << e.what());
      return;
    }
  }
}

void
CaModule::handleStatus(const Interest& request, const CaItem& caItem)
{
  // STATUS Naming Convention: /CA-prefix/CA/_STATUS/{Request-ID JSON}/[Signature components]
  _LOG_TRACE("Handle STATUS request");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Interest with bad signature.");
    return;
  }

  std::string challengeType = certRequest.getChallengeType();
  auto challenge = m_challenges.find(challengeType);
  if (challenge == m_challenges.end()) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->second->handleChallengeRequest(request, certRequest);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);
}

void
CaModule::handleDownload(const Interest& request, const CaItem& caItem)
{
  // DOWNLOAD Naming Convention: /CA-prefix/CA/_DOWNLOAD/{Request-ID JSON}

  NDN_LOG_INFO("<< I: DOWNLOAD: request by MT for new certificate");

  Data result;
  result.setName(request.getName());
  if (readString(request.getName().at(-1)) == "ANCHOR") {
    JsonSection contentJson;

    const auto& pib = m_keyChain.getPib();
    auto identity = pib.getIdentity(caItem.m_caName);
    auto cert = identity.getDefaultKey().getDefaultCertificate();

    // ca-prefix
    Name caName = caItem.m_caName;
    caName.append("CA");
    contentJson.put("ca-prefix", caName.toUri());

    // ca-info
    std::string caInfo;
    if (caItem.m_caInfo == "") {
      caInfo = "Issued by " + cert.getSignature().getKeyLocator().getName().toUri();
    }
    else {
      caInfo = caItem.m_caInfo;
    }
    contentJson.put("ca-info", caInfo);

    // probe
    contentJson.put("probe", caItem.m_probe);

    // ca-target list
    contentJson.put("target-list", caItem.m_targetedList);

    // certificate
    std::stringstream ss;
    io::save(cert, ss);
    contentJson.put("certificate", ss.str());

    result.setContent(dataContentFromJson(contentJson));
  }
  else {
    JsonSection requestIdJson = jsonFromNameComponent(request.getName(), caItem.m_caName.size() + 2);
    std::string requestId = requestIdJson.get(JSON_REQUEST_ID, "");
    security::v2::Certificate signedCert;
    try {
      signedCert = m_storage->getCertificate(requestId);
    }
    catch (const std::exception& e) {
      _LOG_ERROR(e.what());
      return;
    }
    result.setContent(signedCert.wireEncode());
  }
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  NDN_LOG_INFO("New certificate downloaded successfully by MT");
}

security::v2::Certificate
CaModule::issueCertificate(const CertificateRequest& certRequest, const CaItem& caItem)
{
  Name certName = certRequest.getCert().getKeyName();
  certName.append("NDNCERT").appendVersion();
  security::v2::Certificate newCert;
  newCert.setName(certName);
  newCert.setContent(certRequest.getCert().getContent());
  _LOG_TRACE("cert request content " << certRequest.getCert());
  SignatureInfo signatureInfo;
  security::ValidityPeriod period(time::system_clock::now(),
                                  time::system_clock::now() + caItem.m_validityPeriod);
  signatureInfo.setValidityPeriod(period);
  security::SigningInfo signingInfo(security::SigningInfo::SIGNER_TYPE_ID,
                                    caItem.m_caName, signatureInfo);
  newCert.setFreshnessPeriod(caItem.m_freshnessPeriod);

  m_keyChain.sign(newCert, signingInfo);
  NDN_LOG_INFO("CA generates new certificate and signs. " << newCert);
  return newCert;
}

CertificateRequest
CaModule::getCertificateRequest(const Interest& request, const Name& caName)
{
  JsonSection requestIdJson = jsonFromNameComponent(request.getName(), caName.size() + 2);
  std::string requestId = requestIdJson.get(JSON_REQUEST_ID, "");
  CertificateRequest certRequest;
  try {
    certRequest = m_storage->getRequest(requestId);
  }
  catch (const std::exception& e) {
    _LOG_ERROR(e.what());
  }
  return certRequest;
}

void
CaModule::onRegisterFailed(const std::string& reason)
{
  _LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

Block
CaModule::dataContentFromJson(const JsonSection& jsonSection)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonSection);
  return makeStringBlock(ndn::tlv::Content, ss.str());
}

JsonSection
CaModule::jsonFromNameComponent(const Name& name, int pos)
{
  std::string jsonString;
  try {
    jsonString = encoding::readString(name.at(pos));
  }
  catch (const std::exception& e) {
    _LOG_ERROR(e.what());
    return JsonSection();
  }
  std::istringstream ss(jsonString);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

} // namespace ndncert
} // namespace ndn
