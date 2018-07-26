#include "c-wrapper.h"
#include "invoke-client.hpp"

extern "C" {

	InvokeClient* newInvokeClient() {
		return new InvokeClient();
	}

        int InvokeClient_Call_Main(InvokeClient* v, char* p_index, char* p_namespace, char* p_challenge) {
		return v->CallClientMain(p_index, p_namespace, p_challenge);
	}

}
