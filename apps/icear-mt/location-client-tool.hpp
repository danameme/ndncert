/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "client-module.hpp"
#include "challenge-module.hpp"

namespace ndn {
namespace ndncert {

class LocationClientTool
{
public:
  LocationClientTool(Face& face, KeyChain& keyChain, const Name& caPrefix, const Certificate& caCert,
                     const std::string& userIdentity);

  void
   errorCb(const std::string& errorInfo);

  void
  newCb(const shared_ptr<RequestState>& state);

  void
  selectCb(const shared_ptr<RequestState>& state);

  void
  downloadCb(const shared_ptr<RequestState>& state);

  void
  validateCb(const shared_ptr<RequestState>& state);

private:
  const std::string LOCATION_CHALLENGE = "LOCATION";
  ClientModule client;
};

} // namespace ndncert
} // namespace ndn
