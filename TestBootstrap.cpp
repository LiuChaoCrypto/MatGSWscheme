
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
// Since the bootstrapping key is a set of MatGSW encryption ciphertext of secret information 2^js_i, it is a huge memory consumption. So here we iteratively calling BootKeyGenOne algorithm, which is used to generate one bootstrapping key for some seceret key 2^js_i. This way the memory consumption is only one MatGSW ciphertext. 
// SO the tesing algorithm is iteratively generate secret key information and use it to homomorphically multiplicate acc VecLWE ciphertext.
void TestBootstrap_uint16(){
	cout << "This is for testing the correctness of bootstrapping with a toy params;" << endl;
	int intputm = 1;
	
	TimeVar t;
	double processingTime(0.0);

	//	TestSecurity60();



	uint32_t params_Q = pow(2, 16), params_N = 10, params_q = 20, params_t = 2, params_n = 10;
	float params_sigma = 2.12;

	cout << "Params is (Q,N,sigma,q,n)=(" << params_Q << "," << params_N << "," << params_sigma << "," << params_q << "," << params_n<<")"<<endl;
	cout << "Input message < " << params_t<<endl;
	cout << "The input is an LWE ecnryption of messge: " << intputm << ";"<<endl<<" if the output decrypts the same message, then procedure success, i.e. homomorphically decrypting the input LWE ciphertext." << endl;

	
	cout << "Beginning bootstrapping." << endl;

	MatGSWparams_uint16 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);

	MatGSWEncryptionScheme_uint16 scheme;

	auto matgswparams = make_shared<MatGSWparams_uint16>(MatGSWpar1);


	auto matsec = scheme.KeyGen(matgswparams);
	
	


	VecLWEparams_uint16 VecLWEpar1(params_N, params_Q, params_sigma, params_q, params_t);
	auto veclwepar = make_shared<VecLWEparams_uint16>(VecLWEpar1);
	VecLWEEncryptionScheme_uint16 VecLWEscheme;


	LWEparams_uint16 Lwepar1(params_n, params_q, params_sigma, params_t);


	auto lwepar = make_shared<LWEparams_uint16>(Lwepar1);
	LWEEncryptionScheme_uint16 LWEscheme;
	auto lwesec = LWEscheme.KeyGen(lwepar);
	//	cout << "\nlwesec=" << lwesec->Gets();

	uint16_t lwemessage = intputm;

	LWEPlaintext_uint16 lwepltext1;
	lwepltext1.Setm(lwemessage);

	shared_ptr<LWEPlaintext_uint16>  lweplptr = make_shared<LWEPlaintext_uint16>(lwepltext1);


	auto lwecipher = LWEscheme.Encrypt(lwepar, lwesec, lweplptr);



	LWEPlaintext_uint16* lweplainresult = new LWEPlaintext_uint16();

	


	BootstrapScheme_uint16 bootscheme;

	auto MatGswOnceKeyGen = bootscheme.BootKeyGenOne(matgswparams, matsec, 0);

	auto RetuLWEcipher = bootscheme.Bootstrapping(matgswparams, veclwepar, lwecipher, matsec, lwesec);
	
	cout << "Bootstrapping finished." << endl;
	LWEparams_uint16 Lwepar2(params_N, params_Q, params_sigma, params_t);



	auto lwepar2 = make_shared<LWEparams_uint16>(Lwepar2);

	LWESecretKey_uint16 lwesec2;
	lwesec2.Sets((matsec->GetS())[0]);
	auto lwesec3 = make_shared<LWESecretKey_uint16>(lwesec2);





	LWEscheme.Decrypt(lwepar2, lwesec3, RetuLWEcipher, lweplainresult);
	cout << "\n Final LWE cipher is an encryption of m=" << lweplainresult->Getm()<<endl;

	if (lweplainresult->Getm() == intputm)cout << "Success!" << endl;
	else { cout << "Fail!" << endl; }

};




void TestBootstrap_uint32() {
	cout << "This is for testing the correctness of bootstrapping for uint32 with a toy params;" << endl;
	int intputm = 1;
	
	TimeVar t;
	double processingTime(0.0);

	//	TestSecurity60();


	uint64_t params_Q = pow(2, 32);
	uint32_t params_N = 10, params_q = 20, params_t = 2, params_n = 10;
	float params_sigma = 2.12;
	cout << "Params is (Q,N,sigma,q,n)=(" << params_Q << "," << params_N << "," << params_sigma << "," << params_q << "," << params_n << ")" << endl;
	cout << "Input message < " << params_t << endl;
	cout << "The input is an LWE ecnryption of messge: " << intputm << ";" << endl << "  if the output decrypts the same message, then procedure success, i.e. homomorphically decrypting the input LWE ciphertext." << endl;


	cout << "Beginning bootstrapping." << endl;
	MatGSWparams_uint32 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);

	MatGSWEncryptionScheme_uint32 scheme;

	auto matgswparams = make_shared<MatGSWparams_uint32>(MatGSWpar1);


	auto matsec = scheme.KeyGen(matgswparams);




	VecLWEparams_uint32 VecLWEpar1(params_N, params_Q, params_sigma, params_q, params_t);
	auto veclwepar = make_shared<VecLWEparams_uint32>(VecLWEpar1);
	VecLWEEncryptionScheme_uint32 VecLWEscheme;


	LWEparams_uint32 Lwepar1(params_n, params_q, params_sigma, params_t);


	auto lwepar = make_shared<LWEparams_uint32>(Lwepar1);
	LWEEncryptionScheme_uint32 LWEscheme;
	auto lwesec = LWEscheme.KeyGen(lwepar);
	//	cout << "\nlwesec=" << lwesec->Gets();

	uint32_t lwemessage = intputm;

	LWEPlaintext_uint32 lwepltext1;
	lwepltext1.Setm(lwemessage);

	shared_ptr<LWEPlaintext_uint32>  lweplptr = make_shared<LWEPlaintext_uint32>(lwepltext1);


	auto lwecipher = LWEscheme.Encrypt(lwepar, lwesec, lweplptr);



	LWEPlaintext_uint32* lweplainresult = new LWEPlaintext_uint32();




	BootstrapScheme_uint32 bootscheme;

	auto MatGswOnceKeyGen = bootscheme.BootKeyGenOne(matgswparams, matsec, 0);

	auto RetuLWEcipher = bootscheme.Bootstrapping(matgswparams, veclwepar, lwecipher, matsec, lwesec);
	LWEparams_uint32 Lwepar2(params_N, params_Q, params_sigma, params_t);



	auto lwepar2 = make_shared<LWEparams_uint32>(Lwepar2);

	LWESecretKey_uint32 lwesec2;
	lwesec2.Sets((matsec->GetS())[0]);
	auto lwesec3 = make_shared<LWESecretKey_uint32>(lwesec2);


	


	LWEscheme.Decrypt(lwepar2, lwesec3, RetuLWEcipher, lweplainresult);
	cout << "\n Final LWE cipher is an encryption of m=" << lweplainresult->Getm()<<endl;

	if (lweplainresult->Getm() == intputm)cout << "Success!" << endl;
	else { cout << "Fail!" << endl; }
};
