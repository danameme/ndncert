#ifndef C_WRAPPER_H
#define C_WRAPPER_H

//This wrapper calls the main function of the client

#ifdef __cplusplus
extern "C" {
#endif
	typedef class InvokeClient InvokeClient;

	InvokeClient* newInvokeClient();

	int InvokeClient_Call_Main(InvokeClient* v, char* p_index, char* p_namespace, char* p_challenge);

#ifdef __cplusplus
}
#endif

#endif //C_WRAPPER_H

