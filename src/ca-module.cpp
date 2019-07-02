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
#include <iostream>
#include "ca-module.hpp"
#include "challenge-module.hpp"
#include "logging.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <unistd.h>
#include <string>
#include <ctime>
#include <cstdlib>


//AutoSeededRandomPool CA_rng;

namespace ndn {
namespace ndncert {
Face m_chall_face;
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
  for (auto prefixId : m_interestFilterIds) {
    m_face.unsetInterestFilter(prefixId);
  }
  for (auto prefixId : m_registeredPrefixIds) {
    m_face.unregisterPrefix(prefixId, nullptr, nullptr);
  }
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
  _LOG_TRACE("Prefix " << localProbePrefix << " got registered");

  std::cout << "CA issuing certifcates for:" << std::endl;

  // register prefixes for each CA
  for (const auto& item : m_config.m_caItems) {
    Name prefix = item.m_caName;
    prefix.append("CA");
    std::cout << prefix << std::endl;

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
	// CERT
        filterId = m_face.setInterestFilter(Name(name).append("_CERT"),
                                              bind(&CaModule::handleCert, this, _2, item));
        m_interestFilterIds.push_back(filterId);

	/*
	filterId = m_face.setInterestFilter(Name(name).append("_KEY"),
						bind(&CaModule::handleKey, this, _2, item));
	m_interestFilterIds.push_back(filterId);
	*/

        /*
	filterId = m_face.setInterestFilter(Name(name).append("_CHALL_RESP"),
                                                bind(&CaModule::handleChallResp, this, _2, item));
        m_interestFilterIds.push_back(filterId);
	*/

        _LOG_TRACE("Prefix " << name << " got registered");
      },
      bind(&CaModule::onRegisterFailed, this, _2));
    m_registeredPrefixIds.push_back(prefixId);
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
   std::cout << "handleLocalhostList called\n";
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
	/*
   // Fetch static certificate based on keyName defined in ca-sqlite.cpp
   auto apCert = m_storage->getAPCert(request);
   // Check if no certificate was returned
   if (apCert.getKeyName().toUri() == "/") {
	   std::cout << "Could not verify Interest, no certificate retrieved from DB\n";
   }
   else {
   	// Check to see if signed interest is signed by the correct AP
   	if (security::verifySignature(request, apCert)){
        	std::cout << "Signed Interest VERIFIED Successfully!!\n";
   	}
   	else{
        	std::cout << "FAILURE: Could Not Verify Signed Interest\n";
   	}
   }
*/
int verificationResult = CaModule::verifyInterest(request);
if (verificationResult == CaVerifyInterest::SUCCESS) {
  // PROBE Naming Convention: /CA-prefix/CA/_PROBE/<Probe Information>
  _LOG_TRACE("Handle PROBE request");

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
  Name identityName = caItem.m_caName;
  identityName.append(identifier);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseProbeJson(identityName, "")));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  _LOG_TRACE("Handle PROBE: generate identity " << identityName);
}
else {
  if (verificationResult == CaVerifyInterest::NO_CERT_FOUND) {
     std::cout << "Could not verify Interest, no certificate retrieved from DB" << std::endl;
  }
  else if (verificationResult == CaVerifyInterest::FAILURE) {
     std::cout << "FAILURE: Could Not Verify Signed Interest" << std::endl;
  }
}

}

void
CaModule::handleNew(const Interest& request, const CaItem& caItem)
{
  // NEW Naming Convention: /CA-prefix/CA/_NEW/<certificate-request>/[signature]
  _LOG_TRACE("Handle NEW request");
  security::v2::Certificate clientCert;
  try {
    clientCert.wireDecode(request.getName().at(caItem.m_caName.size() + 2).blockFromValue());
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Unrecognized certificate request " << e.what());
    std::cout << "Unrecognized certificate request " << e.what() << std::endl;
    return;
  }

  if (!security::verifySignature(clientCert, clientCert)) {
    _LOG_TRACE("Cert request with bad signature.");
    std::cout << "Cert request with bad signature." <<std::endl;
    return;
  }
  if (!security::verifySignature(request, clientCert)) {
    _LOG_TRACE("Interest with bad signature.");
    std::cout << "Interest with bad signature." << std::endl;
    return;
  }

  auto pubMat = clientCert.getPublicKey();
  mtPubKey.loadPkcs8(pubMat.data(),pubMat.size());

  std::string requestId = std::to_string(random::generateWord64());
  CertificateRequest certRequest(caItem.m_caName, requestId, clientCert);
  certRequest.setStatus(ChallengeModule::WAIT_SELECTION);
  try {
    m_storage->addRequest(certRequest);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot add new request instance " << e.what());
    std::cout << "Cannot add new request instance " << e.what() << std::endl;
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseNewJson(requestId, certRequest.getStatus(),
                                                           caItem.m_supportedChallenges)));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

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
  _LOG_TRACE("SELECT request choosing challenge " << challengeType);
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);
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
  // Generate a challenge
  if(challengeType == "LOCATION"){
    //unsigned int time_ui = time(0);
    //srand(time(NULL));
    srand((unsigned)std::time(0));
    //int number1 = rand() % 999999999 + 100000;
    //int number2 = rand() % 10 + 100;

    int RN = rand() % 99999999 + 1;
    std::string rand_enc = to_string(RN);

    auto buff = mtPubKey.encrypt(reinterpret_cast<const uint8_t *>(rand_enc.data()), rand_enc.size());

    //int finalChall = number1/number2;
    //std::string plain = to_string(number1) + "/" + to_string(number2);
    // Store result for future comparison
    challSent = rand_enc;
    //std::cout << "Sent challenge: " << rand_enc << std::endl;


    //std::string cipher;
    //challSent = plain;
    //RSAES_OAEP_SHA_Encryptor e(mobilePub);
	/*
    StringSource ss1(plain, true,
        new PK_EncryptorFilter(CA_rng, e,
                new StringSink(cipher)
        ) // PK_EncryptorFilter
    ); // StringSource
    */
    //exit(0);
    Data result;
    result.setName(request.getName());
    result.setContent(buff);
    //result.setContent(reinterpret_cast<const uint8_t*>(cipher.data()), cipher.size());
    m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
    m_face.put(result);

  }

  else{
  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);


  }

 if (caItem.m_statusUpdateCallback) {
    caItem.m_statusUpdateCallback(certRequest);
  }

}

void
CaModule::handleValidate(const Interest& request, const CaItem& caItem)
{
  // VALIDATE Naming Convention: /CA-prefix/CA/_VALIDATE/{Request-ID JSON}/<ChallengeID>/
  // {Param JSON}/[Signature components]
  _LOG_TRACE("Handle VALIDATE request");
  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  std::string challengeType = certRequest.getChallengeType();
  if(challengeType == "LOCATION"){
     Block b = request.getApplicationParameters();

     auto dec = m_keyChain.getTpm().decrypt(b.value(), b.value_size(), myCert.getKeyName());
     std::string recovered(dec->begin(),dec->end());
     //std::cout << "Recovered " << recovered << std::endl;
     if (recovered == challSent) {
       std::cout << "Challenge passed!\n";

     }
     else {
       std::cout << "Challenge failed\n";
       return;
     }
  }

  else{
   if(!security::verifySignature(request, certRequest.getCert())){
     _LOG_TRACE("Interest with bad signature");
   }
   std::cout << "Verification successful\n";
  }
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);
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
  //std::string message2 = to_string(rand()%99999999+10000000);
  //sentMessage = message2;
  Data result;
  Name dataName(request.getName());
  //dataName.append(message2);
  result.setName(dataName);
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

  if (certRequest.getStatus() == ChallengeModule::SUCCESS) {
    auto issuedCert = issueCertificate(certRequest, caItem);
    if (caItem.m_statusUpdateCallback) {
      certRequest.setCert(issuedCert);
      caItem.m_statusUpdateCallback(certRequest);
    }
    try {
      m_storage->addCertificate(certRequest.getRequestId(), issuedCert);
      m_storage->deleteRequest(certRequest.getRequestId());
      _LOG_TRACE("New Certificate Issued " << issuedCert.getName());
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
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);
}

void
CaModule::handleDownload(const Interest& request, const CaItem& caItem)
{
	/*
  if(request.hasApplicationParameters()){
  	Block signedMessage = request.getApplicationParameters();
  	std::string signedChall((char*)signedMessage.value(),signedMessage.value_size());
  	SecByteBlock signature((const byte*)signedChall.data(),signedChall.size());

  	RSASS<PSS, SHA1>::Verifier verifier( mobilePub );

  	// Verify
  	bool result = verifier.VerifyMessage( (const byte*)sentMessage.c_str(),
  	sentMessage.length(), signature, signature.size() );

  	// Result
  	if( true == result ) {
  		std::cout << "Signature on message verified" << std::endl;
  	}
  	else {
        	std::cout << "Message verification failed" << std::endl;
		return;
        }
  }
  */
  //std::cout << "GOT DOWNLOAD\n";
  int verificationResult = CaModule::verifyInterest(request);
  if (verificationResult == CaVerifyInterest::SUCCESS) {
  // DOWNLOAD Naming Convention: /CA-prefix/CA/_DOWNLOAD/{Request-ID JSON}
  _LOG_TRACE("Handle DOWNLOAD request");

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
      //std::cout << "error?\n";
      return;
    }
    result.setContent(signedCert.wireEncode());
  }
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);
  //std::cout << "cert sent\n";
}
else {
  if (verificationResult == CaVerifyInterest::NO_CERT_FOUND) {
     std::cout << "Could not verify Interest, no certificate retrieved from DB" << std::endl;
  }
  else if (verificationResult == CaVerifyInterest::FAILURE) {
     std::cout << "FAILURE: Could Not Verify Signed Interest" << std::endl;
  }
}

}


void
CaModule::handleCert(const Interest& request, const CaItem& caItem)
{
  // CERT Naming Convention: /CA-prefix/CA/_CERT
  _LOG_TRACE("Handle CERT request");
  std::string int_name = request.getName().toUri();

  if (int_name.find("_DATACERT") != std::string::npos) {
	std::string post_name = int_name.substr(int_name.find("_DATACERT") + 10);
	std::string pre_name = int_name.substr(0, int_name.find("CA"));

	// Fetch static certificate based on keyName defined in ca-sqlite.cpp
        auto cert = m_storage->getDataCertificate(pre_name + post_name);

	Data result;
        result.setName(request.getName());
        result.setFreshnessPeriod(time::seconds(4));
        result.setContent(cert.wireEncode());
        m_keyChain.sign(result, signingByIdentity(caItem.m_caName));

        m_face.put(result);
  }
  else {
	  //std::cout << "THIS???\n\n\n\n";
  	auto identity = m_keyChain.getPib().getIdentity(Name(caItem.m_caName));
  	auto cert = identity.getDefaultKey().getDefaultCertificate();
	myCert = cert;

  	Data result;
  	result.setName(request.getName());
  	result.setFreshnessPeriod(time::seconds(4));
  	result.setContent(cert.wireEncode());
  	m_keyChain.sign(result, signingByIdentity(caItem.m_caName));

  	m_face.put(result);
  }

}

/*
void
CaModule::handleChallResp(const Interest& request, const CaItem& caItem)
{
  std::string int_name = request.getName().toUri();
  std::cout << int_name << std::endl;
  // Since we know the length of the random number
  std::string partOne = int_name.substr(int_name.find("_CHALL_RESP/")+12);
  std::string message = partOne.substr(0, partOne.find("/"));
  int ourSeed = stoi(message);
  std::cout << message << std::endl;
  RSASS<PSS, SHA1>::Signer signer( m_privKey );

  // Create signature space
  size_t length = signer.MaxSignatureLength();
  std::cout << length <<std::endl;
  SecByteBlock signature( length );

        // Sign message
  signer.SignMessage( rng, (const byte*) message.c_str(),
  				message.length(), signature );

  std::string token = std::string((char*)signature.data(),signature.size());

  srand(ourSeed);
  //std::string message2 = to_string(rand()%99999999+10000000);
  //sentMessage = message2;
  Data result;
  Name dataName(request.getName());
  //dataName.append(message2);
  //result.setName(request.getName().append(message2));
  result.setName(dataName);
  std::cout << result.getName().toUri() << std::endl;
  result.setFreshnessPeriod(time::seconds(4));
  //Block signedMessage(reinterpret_cast<const uint8_t*>(token.data()), token.size());
  //Block nothing;
  result.setContent(reinterpret_cast<const uint8_t*>(token.data()), token.size());
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

}

*/

/*
void
CaModule::handleKey(const Interest& request, const CaItem& caItem)
{
  _LOG_TRACE("Handle PubKey request");


  Block MTpub = request.getApplicationParameters();
  std::string MTpubMaterial((char*)MTpub.value(), MTpub.value_size());


  RSA::PublicKey MTPublicKey;
  StringSource stringSource(MTpubMaterial,true);
  MTPublicKey.BERDecode(stringSource);
  mobilePub = MTPublicKey;



  // Generate public/private RSA pair
  parameters.GenerateRandomWithKeySize(CA_rng, 512);
  RSA::PublicKey publicKey( parameters );
  RSA::PrivateKey privateKey( parameters );
  m_pubKey = publicKey;
  m_privKey = privateKey;

  // Convert public key to string so we can send it to MT
  std::string pubKeyMaterial;
  StringSink stringSink(pubKeyMaterial);
  publicKey.DEREncode(stringSink);

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(time::seconds(4));
  Block pubKeyContent(reinterpret_cast<const uint8_t*>(pubKeyMaterial.data()), pubKeyMaterial.size());
  result.setContent(pubKeyContent);
  m_keyChain.sign(result, signingByIdentity(caItem.m_caName));
  m_face.put(result);

}
*/



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
  _LOG_TRACE("new cert got signed" << newCert);
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

CaModule::CaVerifyInterest
CaModule::verifyInterest(const Interest& request)
{
   return CaVerifyInterest::SUCCESS;
   // Fetch static certificate based on keyName defined in ca-sqlite.cpp
   auto apCert = m_storage->getAPCert(request);

   // Check if no certificate was returned
   if (apCert.getKeyName().toUri() == "/") {
	   return CaVerifyInterest::NO_CERT_FOUND;
   }
   else {
        // Check to see if signed interest is signed by the correct AP
        if (security::verifySignature(request, apCert)){
		return CaVerifyInterest::SUCCESS;
        }
        else{
		return CaVerifyInterest::FAILURE;
        }
   }

}

} // namespace ndncert
} // namespace ndn
