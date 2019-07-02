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

#ifndef NDNCERT_LOCATION_CHALLENGE_HPP
#define NDNCERT_LOCATION_CHALLENGE_HPP

#include "../challenge-module.hpp"
#include <ndn-cxx/util/time.hpp>

namespace ndn {
namespace ndncert {

class LocationChallenge : public ChallengeModule
{
public:
  LocationChallenge();

  // Location challenge specifics
  JsonSection
  processLocalhopInterest(const Interest& interest, CertificateRequest& request);

  JsonSection
  genLocalhopParamsJson(const std::string& status, const std::list<std::string>& paramList);

  // common challenge methods
PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  JsonSection
  processSelectInterest(const Interest& interest, CertificateRequest& request) override;

  JsonSection
  processValidateInterest(const Interest& interest, CertificateRequest& request) override;

  std::list<std::string>
  getSelectRequirements() override;

  std::list<std::string>
  getValidateRequirements(const std::string& status) override;

  JsonSection
  doGenSelectParamsJson(const std::string& status,
                        const std::list<std::string>& paramList) override;

  JsonSection
  doGenValidateParamsJson(const std::string& status,
                          const std::list<std::string>& paramList) override;

  void
  doRegisterChallengeActions(Face& face, KeyChain& keyChain, const PrevalidateCallback& prevalidate) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static std::tuple<time::system_clock::TimePoint, std::string, std::string>
  parseStoredSecrets(const JsonSection& storedSecret);

  static JsonSection
  generateStoredSecrets(const time::system_clock::TimePoint& tp,
                        const std::string& secretCode1, const std::string& secretCode2);

public:
  static const Name LOCALHOP_VALIDATION_PREFIX;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const std::string NEED_CODE;
  static const std::string WRONG_CODE;

  static const std::string FAILURE_TIMEOUT;

  static const std::string JSON_CODE_TP;
  static const std::string JSON_PIN_CODE1;
  static const std::string JSON_PIN_CODE2;

  const time::seconds m_secretLifetime = 60_s;

  // These make sense only for CA and must be initialized during doRegisterChallengeActions
  Face* m_face = nullptr;
  KeyChain* m_keyChain = nullptr;
  ScopedInterestFilterHandle m_localhopRegistration;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_LOCATION_CHALLENGE_HPP
