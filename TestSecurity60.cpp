
#include<iostream>

#include"MatGSWcore.h"
#include"MatGSW.h"
#include"VecLWE.h"
#include"VecLWEcore.h"
#include"LWE.h"
#include"LWEcore.h"
#include"Bootstrapcore.h"
#include"TestTime.h"
#include"TestSecurity60.h"

using namespace std;

void TestSecurity60_uint16(Method set){
	
	TimeVar t;
	double processingTime(0.0);

	uint32_t params_Q = pow(2, 16), params_N = 400, params_q, params_t = 2, params_n = 256, params_q2 = pow(2, 9);
	float params_sigma = 2.12;

	switch (set) {
	case HAOscheme:
			params_q = 7;
			break;
	case MatGSWscheme:
		params_q = pow(2, 9);
		break;		  
	}
	MatGSWparams_uint16 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);
	MatGSWEncryptionScheme_uint16 scheme;
	auto matgswparams = make_shared<MatGSWparams_uint16>(MatGSWpar1);

	TIC(t);
	auto matsec = scheme.KeyGen(matgswparams);

	processingTime = TOC_US(t);
	std::cout
		<< "\nMatGSW SecretKeyGen: "
		<< processingTime << "us" << std::endl;
	MatGSWPlaintext_uint16* resultM = new MatGSWPlaintext_uint16();

	auto matgswtestm = scheme.SetPerM(matgswparams, 3);

	VecLWEparams_uint16 VecLWEpar1(params_N, params_Q, params_sigma, params_q, params_t);
	auto veclwepar = make_shared<VecLWEparams_uint16>(VecLWEpar1);
	VecLWEEncryptionScheme_uint16 VecLWEscheme;

	vector<uint16_t> veclwemessage(params_q);
	veclwemessage[0] = 2;
	veclwemessage[1] = 1;
	veclwemessage[2] = 3;
	veclwemessage[3] = 0;
	VecLWEPlaintext_uint16 lweplain1;
	lweplain1.SetM(veclwemessage);

	auto lweplain = make_shared<VecLWEPlaintext_uint16>(lweplain1);

	VecLWESecretKey_uint16 veclwesecwithmatlwe;
	veclwesecwithmatlwe.SetS(matsec->GetS());
	auto vec_sec = make_shared<VecLWESecretKey_uint16>(veclwesecwithmatlwe);

	TIC(t);
	auto veclwecipher = VecLWEscheme.Encrypt(veclwepar, vec_sec, lweplain);
	processingTime = TOC_US(t);
	std::cout
		<< "\nVecLWE Encrypt: "
		<< processingTime << "us" << std::endl;
	VecLWEPlaintext_uint16* plainresult = new VecLWEPlaintext_uint16();

	long NN = (params_N + params_q) * matgswparams->Getl();

	vector<uint16_t> testA(NN);

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	
		for (long j = 0; j <NN; j++)
		{
			if (cnt == 0)
				(*RNG_new_1).call_bytes(output_2, 32);
			testA[j] = (((uint16_t*)output_2)[cnt]);
			cnt = (cnt + 1) % 16;
		}
	TIC(t);
	auto vec_cipher = scheme.VecVecMul(matgswparams, veclwepar, testA, veclwecipher);

	processingTime = TOC_US(t);
	std::cout
		<< "\nOnce Vec Mul Vec taken : "
		<< processingTime << "us" << std::endl;
	double oneboot;
	switch (set) {
	case HAOscheme:
		oneboot = processingTime / 1000 * pow((long)(params_N + params_q), 2) / 1000 * 16;
		cout << "Bootstrapping Time For onece MatMulMat is VecVecMul*(N+r)^2*logQ=" << oneboot<<"s";
		cout<<"\n All time for bootstrapping is oneboot*3*(n*logq+q)="<< oneboot * 2 * 3 * ((double)params_n * 9 + (double)params_q2 / 2) / 3600 << "h";
		break;
	case MatGSWscheme:
		oneboot = processingTime / 1000 * (params_N + params_q) / 1000 ;
		cout << "Bootstrapping Time For onece MatMulVec is VecVecMul*(N+q)=" << oneboot << "s";
		cout << "\n All time for bootstrapping is oneboot*n*logq=" << oneboot * (double)params_n * 9 / 3600 << "h";
		break;

	}
	switch (set) {
	case MatGSWscheme:
		cout << "Plase waiting. MatGSW encryption take about 20 minutes";
		break;
	}

	TIC(t);
	auto cipher = scheme.Encrypt_Fast(matgswparams, matsec, matgswtestm);
	processingTime = TOC(t);
	std::cout
		<< "\nMatGSW Encrypt: "
		<< processingTime << "ms" << std::endl;
}



void TestSecurity128_uint16(Method set) {

	TimeVar t;
	double processingTime(0.0);
	uint32_t params_Q = pow(2, 16), params_N = 700, params_q, params_t = 2, params_n = 500, params_q2 = pow(2, 9);
	float params_sigma = 2.12;
	switch (set) {
	case HAOscheme:
		params_q = 7;
		break;
	case MatGSWscheme:
		params_q = pow(2, 10);
		break;
	}
	cout << "When q=" << params_q << endl;
	MatGSWparams_uint16 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);
	MatGSWEncryptionScheme_uint16 scheme;

	auto matgswparams = make_shared<MatGSWparams_uint16>(MatGSWpar1);

	TIC(t);
	auto matsec = scheme.KeyGen(matgswparams);

	processingTime = TOC_US(t);
	std::cout
		<< "\nMatGSW SecretKeyGen: "
		<< processingTime << "us" << std::endl;

	MatGSWPlaintext_uint16* resultM = new MatGSWPlaintext_uint16();

	auto matgswtestm = scheme.SetPerM(matgswparams, 3);

	VecLWEparams_uint16 VecLWEpar1(params_N, params_Q, params_sigma, params_q, params_t);
	auto veclwepar = make_shared<VecLWEparams_uint16>(VecLWEpar1);
	VecLWEEncryptionScheme_uint16 VecLWEscheme;

	vector<uint16_t> veclwemessage(params_q);
	veclwemessage[0] = 2;
	veclwemessage[1] = 1;
	veclwemessage[2] = 3;
	veclwemessage[3] = 0;
	VecLWEPlaintext_uint16 lweplain1;
	lweplain1.SetM(veclwemessage);

	auto lweplain = make_shared<VecLWEPlaintext_uint16>(lweplain1);

	VecLWESecretKey_uint16 veclwesecwithmatlwe;
	veclwesecwithmatlwe.SetS(matsec->GetS());
	auto vec_sec = make_shared<VecLWESecretKey_uint16>(veclwesecwithmatlwe);

	TIC(t);
	auto veclwecipher = VecLWEscheme.Encrypt(veclwepar, vec_sec, lweplain);
	processingTime = TOC_US(t);
	std::cout
		<< "\nVecLWE Encrypt: "
		<< processingTime << "us" << std::endl;
	VecLWEPlaintext_uint16* plainresult = new VecLWEPlaintext_uint16();

	long NN = (params_N + params_q) * matgswparams->Getl();

	vector<uint16_t> testA(NN);

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;

	for (long j = 0; j < NN; j++)
	{
		if (cnt == 0)
			(*RNG_new_1).call_bytes(output_2, 32);
		testA[j] = (((uint16_t*)output_2)[cnt]);
		cnt = (cnt + 1) % 16;
	}
	TIC(t);
	auto vec_cipher = scheme.VecVecMul(matgswparams, veclwepar, testA, veclwecipher);

	processingTime = TOC_US(t);
	std::cout
		<< "\nOnce Vec Mul Vec taken : "
		<< processingTime << "us" << std::endl;
	double oneboot;
	switch (set) {
	case HAOscheme:
		oneboot = processingTime / 1000 * pow((long)(params_N + params_q), 2) / 1000 * 16;
		cout << "Bootstrapping Time For onece MatMulMat is VecVecMul*(N+r)^2*logQ=" << oneboot << "s";
		cout << "\n All time for bootstrapping is oneboot*3*(n*logq+q)=" << oneboot *2* 3 * ((double)params_n * 9 + (double)params_q2/2) / 3600 << "h";
		break;
	case MatGSWscheme:
		oneboot = processingTime / 1000 * (params_N + params_q) / 1000;
		cout << "Bootstrapping Time For onece MatMulVec is VecVecMul*(N+q)=" << oneboot << "s";
		cout << "\n All time for bootstrapping is oneboot*n*logq=" << oneboot * (double)params_n * 9 / 3600 << "h";
		break;
	}
	switch (set) {
	case MatGSWscheme:
		cout << "Plase waiting. MatGSW encryption take minutes";
		break;
	}

	TIC(t);
	auto cipher = scheme.Encrypt_Fast(matgswparams, matsec, matgswtestm);
	processingTime = TOC(t);
	std::cout
		<< "\nMatGSW Encrypt: "
		<< processingTime << "ms" << std::endl;
}








//----------------------------------------------------



void TestSecurity_uint32(Method set, int security) {

	uint64_t params_Q ;
	uint32_t params_N , params_q, params_t, params_n,params_q2,params_L,params_l;
	float params_sigma = 2.12,params_sigmaLWE=1.5;//params_sigma is for MatGSW params_sigmaLWE is for input LWE ciphertext;
	TimeVar t;
	double processingTime(0.0);
	if (security == 128)
	{
		params_Q = pow(2, 32);
		params_N = 1500, params_q, params_t = 3, params_n = 500;
		


		switch (set) {
		case HAOscheme:
			params_q = 10;
			params_q2= pow(2, 11);
			break;
		case MatGSWscheme:
			params_q = pow(2, 11);
			break;

		}


	}
	else if (security == 192)
	{
		 params_Q = pow(2, 32);
		params_N = 2000, params_q, params_t = 3, params_n = 700;
		


		switch (set) {
		case HAOscheme:
			params_q = 10;
			params_q2 = pow(2, 11);
			break;
		case MatGSWscheme:
			params_q = pow(2, 11);
			break;

		}

	}
	else if (security == 256) {
		 params_Q = pow(2, 32);
		 params_N = 2500, params_q, params_t = 3, params_n = 1000;
	

		switch (set) {
		case HAOscheme:
			params_q = 10;
			params_q2 = pow(2, 12);
			break;
		case MatGSWscheme:
			params_q = pow(2, 12);
			break;

		}


	}
	

	params_L = log(params_Q) / log(2);
	switch (set) {
	case HAOscheme:
		params_l = log(params_q2) / log(2);
		break;
	case MatGSWscheme:
		params_l = log(params_q) / log(2);
		break;

	}
	




	cout << "\nThe program is used to roughly estimate the running time of KeyGen and Bootstrapping algorithm." << endl;
	cout << "The scheme is " << set;
	cout << "Params is (Q,N,sigma,q,n,sigma',t)=(" << params_Q << "," << params_N << "," << params_sigma << ",";
	switch (set) {
	case HAOscheme:
		cout << params_q2;
		break;
	case MatGSWscheme:
		cout << params_q;
		break;
	} 
	cout<< "," << params_n <<","<<params_sigmaLWE<<","<<params_t<<")" << endl;
	cout << "Parameters security is " << security << "bit"<<endl;

	MatGSWparams_uint32 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);

	MatGSWEncryptionScheme_uint32 scheme;

	auto matgswparams = make_shared<MatGSWparams_uint32>(MatGSWpar1);

	TIC(t);
	auto matsec = scheme.KeyGen(matgswparams);

	processingTime = TOC_US(t);
	std::cout
		<< "\nMatGSW SecretKeyGen: "
		<< processingTime << "us" << std::endl;

	MatGSWPlaintext_uint32* resultM = new MatGSWPlaintext_uint32();

	auto matgswtestm = scheme.SetPerM(matgswparams, 3);

	VecLWEparams_uint32 VecLWEpar1(params_N, params_Q, params_sigma, params_q, params_t);
	auto veclwepar = make_shared<VecLWEparams_uint32>(VecLWEpar1);
	VecLWEEncryptionScheme_uint32 VecLWEscheme;

	vector<uint32_t> veclwemessage(params_q);
	veclwemessage[0] = 2;
	veclwemessage[1] = 1;
	veclwemessage[2] = 3;
	veclwemessage[3] = 0;
	VecLWEPlaintext_uint32 lweplain1;
	lweplain1.SetM(veclwemessage);

	auto lweplain = make_shared<VecLWEPlaintext_uint32>(lweplain1);

	VecLWESecretKey_uint32 veclwesecwithmatlwe;
	veclwesecwithmatlwe.SetS(matsec->GetS());
	auto vec_sec = make_shared<VecLWESecretKey_uint32>(veclwesecwithmatlwe);

	TIC(t);
	auto veclwecipher = VecLWEscheme.Encrypt(veclwepar, vec_sec, lweplain);
	processingTime = TOC_US(t);
	std::cout
		<< "\nVecLWE Encrypt: "
		<< processingTime << "us" << std::endl;
	VecLWEPlaintext_uint32* plainresult = new VecLWEPlaintext_uint32();

	long NN = (params_N + params_q) * matgswparams->Getl();


	vector<uint32_t> testA(NN);

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;

	for (long j = 0; j < NN; j++)
	{
		if (cnt == 0)
			(*RNG_new_1).call_bytes(output_2, 32);
		testA[j] = (((uint32_t*)output_2)[cnt]);
		cnt = (cnt + 1) % 16;
	}
	//	if(i%40==0)cout << "*";

	TIC(t);
	auto vec_cipher = scheme.VecVecMul(matgswparams, veclwepar, testA, veclwecipher);

	processingTime = TOC_US(t);
	std::cout
		<< "\nVector product takes : "
		<< processingTime << "us" << std::endl;
	double oneboot;
	switch (set) {
	case HAOscheme:
		oneboot = processingTime / 1000 * pow((long)(params_N + params_q), 2) / 1000 *params_L;
		cout << "Bootstrapping time in  HAOscheme for onece MatGSW ciphertext "<<endl<<"homomorphic multiplication is VecProTime*(N+r)^2*logQ=" << oneboot << "s";
		cout << "\n All time  in  HAOscheme for bootstrapping is OneMatMulMat*3*(n*logq+q)=" << oneboot * 2 * params_t * ((double)params_n * params_l + (double)params_q2 / 2) / 3600 << "h";
		break;
	case MatGSWscheme:
		oneboot = processingTime / 1000 * (params_N + params_q) / 1000;
		cout << "Bootstrapping time in MatGSWscheme for onece MatGSW ciphertext and VecLWE ciphertext" << endl << " multiplication is VecProTime*(N+q)=" << oneboot << "s";
		cout << "\n All time in MatGSWscheme for bootstrapping is OneMatMulVec*n*logq=" << oneboot * (double)params_n * params_l / 3600 << "h";
		break;
	}
	double onetime=0;
	
	scheme.Encrypt_Fast_TEST(matgswparams, matsec, matgswtestm,onetime);
	
	onetime = onetime / 1000;
	switch (set) {
	case HAOscheme:
		cout << "\nKeyGen time in HAOscheme for all MatGSW ciphertext  is OneMatGenTime*(3t*n*log(q)+qt/2+1)=" << onetime*(3*params_t*params_n*params_l+params_q2*params_t/2+1)/3600 << "h"<<endl;
		break;
	case MatGSWscheme:
		cout <<  "\nKeyGen time in MatGSWscheme for all MatGSW ciphertext is OneMatGenTime*n*log(q)= " << onetime * params_n * params_l/ 3600 << "h"<<endl;
		break;

	}


}
