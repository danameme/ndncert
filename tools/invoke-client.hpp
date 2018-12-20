#ifndef INVOKE_CLIENT_H
#define INVOKE_CLIENT_H

//This class defines one function to call the client's main function. This is what the c-wrapper function calls

#include <string>

class InvokeClient {

	public:
		InvokeClient();
		int CallClientMain(std::string p_ca_prefix, std::string p_user_identity, std::string p_challenge);

};
#endif

