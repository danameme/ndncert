#include <iostream>

class NdnCertClientShLib {

public:
	NdnCertClientShLib();
	int RunNdnCertClient(std::string p_ca_prefix, std::string p_user_identity, std::string p_challenge);
};