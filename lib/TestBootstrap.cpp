
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


void TestBootstrap_uint32() {
	cout << "Test the correctness of bootstrapping;" << endl;
	
	
	TimeVar t;
	double processingTime(0.0);


	uint64_t params_Q = pow(2, 32);
	uint32_t params_N = 100, params_q = 100, params_t = 4, params_n = 10;
	int inputm;
	cout << "Please input a int message in [0," << params_t - 1 << "]:\n";
	cin >> inputm;
	if ((inputm >= 4) || (inputm < 0)) { cout << "Wrong inputs!"; return; }
	float params_sigma = 2.12;
	cout << "Params is (Q,N,sigma,q,n)=(" << params_Q << "," << params_N << "," << params_sigma << "," << params_q << "," << params_n << ")" << endl;
	cout << "Input message is in [0," << params_t-1<<"]" << endl;
	cout << "The input is an LWE ecnryption of messge: " << inputm << ";" << endl << "If the bootstrapped ciphertext decrypts the same message with the input message, then procedure success." << endl;

	cout << "Begin bootstrapping" << endl;
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
	uint32_t lwemessage = inputm;

	LWEPlaintext_uint32 lweplaine1;
	lweplaine1.Setm(lwemessage);

	shared_ptr<LWEPlaintext_uint32>  lweplainptr = make_shared<LWEPlaintext_uint32>(lweplaine1);

	auto lweciphertext = LWEscheme.Encrypt(lwepar, lwesec, lweplainptr);
	LWEPlaintext_uint32* lweplainresult = new LWEPlaintext_uint32();
	BootstrapScheme_uint32 bootscheme;
	auto MatGswOnceKeyGen = bootscheme.BootKeyGenOne(matgswparams, matsec, 0);
	auto RetuLWEcipher = bootscheme.Bootstrapping(matgswparams, veclwepar, lweciphertext, matsec, lwesec);
	cout << "Decrypt bootstrapped ciphertext\n";
	LWEparams_uint32 Lwepar2(params_N, params_Q, params_sigma, params_t);
	auto lwepar2 = make_shared<LWEparams_uint32>(Lwepar2);
	LWESecretKey_uint32 lwesec2;
	lwesec2.Sets((matsec->GetS())[0]);
	auto lwesec3 = make_shared<LWESecretKey_uint32>(lwesec2);
	LWEscheme.Decrypt(lwepar2, lwesec3, RetuLWEcipher, lweplainresult);
	cout << "Final LWE cipher is an encryption of m=" << lweplainresult->Getm()<<endl;
	if (lweplainresult->Getm() == inputm)cout << "Success!" << endl;
	else { cout << "Fail!" << endl; }
};


void TestBootstrapBool_uint32() {
	cout << "\n\nEvaluate Boolean Gates;" << endl;
	int intputm1;
	int intputm2;
	cout << "Please input two bit, after enter one bit, press Enter to enter next one. Input must be 0 or 1:\n";
	cin>>intputm1;
	cin >> intputm2;
	if ((intputm1 != 0) && (intputm1 != 1))
	{
		cout << "Wrong inputs! Please input 0 or 1"; return;
	}
	if ((intputm2 != 0) && (intputm2 != 1))
	{
		cout << "Wrong inputs! Please input 0 or 1"; return;
	}
	cout << "\n Input two bits is " << intputm1 << " and " << intputm2;

	cout << "\n Please input the Boolea Gates type. Input one of number in {1,2,3,4,5,6}, for every number, it corresponding to {OR,NOR,AND,NAND,XOR,XNOR} gate, respectly:";
	
	int bl;
	Boolean BL;
	cin >> bl;
	switch (bl)
	{
	case 1:BL = OR;
        cout<<"Input Boolean Gate is OR";
		break;
	case 2:BL = NOR;
        cout<<"Input Boolean Gate is NOR";
		break;
	case 3:BL = AND;
        cout<<"Input Boolean Gate is AND";
		break;
	case 4:BL = NAND;
        cout<<"Input Boolean Gate is NAND";
		break;
	case 5:BL = XOR;
        cout<<"Input Boolean Gate is XOR";
		break;
	case 6:BL = XNOR;
        cout<<"Input Boolean Gate is XNOR";
		break;
	default: cout << "Wrong input!";
		return;
		break;
	}
	TimeVar t;
	double processingTime(0.0);
	//	TestSecurity60();
	uint64_t params_Q = pow(2, 32);
	uint32_t params_N = 100, params_q = 100, params_t = 4, params_n = 10;
	float params_sigma = 2.12;
	cout << "\nParams is (Q,N,sigma,q,n)=(" << params_Q << "," << params_N << "," << params_sigma << "," << params_q << "," << params_n << ")" << endl;

	cout << "Begin evaluate" << endl;
	MatGSWparams_uint32 MatGSWpar1(params_N, params_Q, params_sigma, params_q, params_n);
	cout << "Encrypt the first message\n";
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
	uint32_t lwemessage_1 = intputm1;
	LWEPlaintext_uint32 lwepltext_1;
	lwepltext_1.Setm(lwemessage_1);
	shared_ptr<LWEPlaintext_uint32>  lweplptr_1 = make_shared<LWEPlaintext_uint32>(lwepltext_1);
	auto lwecipher_1 = LWEscheme.Encrypt(lwepar, lwesec, lweplptr_1);
	cout << "Encrypt the second message\n";
	uint32_t lwemessage_2 = intputm2;
	LWEPlaintext_uint32 lwepltext_2;
	lwepltext_2.Setm(lwemessage_2);
	shared_ptr<LWEPlaintext_uint32>  lweplptr_2 = make_shared<LWEPlaintext_uint32>(lwepltext_2);
	auto lwecipher_2 = LWEscheme.Encrypt(lwepar, lwesec, lweplptr_2);
	cout << "Add two ciphertexts\n";
	auto lwecipher = LWEscheme.LWEadd(lwepar, lwecipher_1, lwecipher_2);
	LWEPlaintext_uint32* lwemresult = new LWEPlaintext_uint32();;
    LWEscheme.Decrypt(lwepar, lwesec, lwecipher, lwemresult);
	if (lwemresult->Getm() != (intputm1 + intputm2)) { cout << "Error is too big, try agin!"; return; }// if m1+m2 is not correct, it means that the error is too big so that decryption failure.
	cout << "Bootstrapping\n";
	LWEPlaintext_uint32* lweplainresult = new LWEPlaintext_uint32();
	BootstrapScheme_uint32 bootscheme;
	auto MatGswOnceKeyGen = bootscheme.BootKeyGenOne(matgswparams, matsec, 0);
	auto RetuLWEcipher = bootscheme.BootstrappingBool(matgswparams, veclwepar, lwecipher, matsec, lwesec,BL);
	cout << "Decrypt bootstrapped ciphertext\n";
	
	LWEparams_uint32 Lwepar2(params_N, params_Q, params_sigma, params_t);

	auto lwepar2 = make_shared<LWEparams_uint32>(Lwepar2);

	LWESecretKey_uint32 lwesec2;
	lwesec2.Sets((matsec->GetS())[0]);
	auto lwesec3 = make_shared<LWESecretKey_uint32>(lwesec2);

	LWEscheme.Decrypt(lwepar2, lwesec3, RetuLWEcipher, lweplainresult);
	cout << "Decryption finish\n";
    cout << "Result is : " << intputm1;
	switch (bl)
	{
	case 1:cout<<" OR ";
		break;
	case 2:cout << " NOR ";
		break;
	case 3:cout << " AND ";
		break;
	case 4:cout << " NAND ";
		break;
	case 5:cout << " XOR ";
		break;
	case 6:cout << " XNOR ";
		break;
	};
	cout<< intputm2 << "="<<lweplainresult->Getm()<<endl;
};
