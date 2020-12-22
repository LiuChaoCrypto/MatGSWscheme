
#include"VecLWE.h"
#include"random.h"


std::shared_ptr<VecLWESecretKey_uint16> VecLWEEncryptionScheme_uint16::KeyGen(
	const std::shared_ptr<VecLWEparams_uint16> params) const {

	uint32_t q = params->Getq();
	uint32_t N = params->GetN();

	VecLWESecretKey_uint16 sec;
	vector<vector<uint16_t>> secret(q);
	for (uint32_t i = 0; i < q; i++)
	{
		secret[i].resize(N);
	}

	unsigned char* seed = new unsigned char[32];
	seed[0] = (unsigned)time(NULL);

	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];

	(*RNG_new_1).init(seed, 32);

	//	(*RNG_new_1).call_bytes(output_2, 32);

	for (long i = 0; i < q; i++)
		for (long j = 0; j < N; j++)
			secret[i][j] = sampler_New(5, 3, output_2, RNG_new_1);

	sec.SetS(secret);
	return make_shared<VecLWESecretKey_uint16>(sec);
}

std::shared_ptr<VecLWECiphertext_uint16> VecLWEEncryptionScheme_uint16::Encrypt(
	const std::shared_ptr<VecLWEparams_uint16> params,
	const std::shared_ptr<const VecLWESecretKey_uint16> sk,
	const std::shared_ptr<const VecLWEPlaintext_uint16> m) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint32_t t = params->Gett();
	uint32_t delta = params->Getdelta();

	vector<vector<uint16_t>> S = sk->GetS();
	vector<uint16_t> message = m->Getm();

	vector<uint16_t> encodem(q);
	for (long i = 0; i < q; i++)
		encodem[i] = delta * message[i];


	VecLWECiphertext_uint16 cipher;
	vector<uint16_t> a(N);
	vector<uint16_t> error(q);
	vector<uint16_t> b(q);

	//Generate vector a
	

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	for (long i = 0; i < N; i++)
	{
			if (cnt == 0)
				(*RNG_new_1).call_bytes(output_2, 32);
			a[i] = (((uint16_t*)output_2)[cnt]);
			cnt = (cnt + 1) % 16;
		}

	cipher.Seta(a);

	//Compute b


	

	for (long i = 0; i < q; i++)
			error[i] = sampler_New(5, 3, output_2, RNG_new_1);



	for (long i = 0; i < q; i++)
	{
		for (long k = 0; k < N; k++)
		{
			b[i] += S[i][k] * a[k];
			
		}
		b[i] += error[i] + encodem[i];
	}
			
	cipher.Setb(b);

	return make_shared<VecLWECiphertext_uint16>(cipher);

};



//
//std::shared_ptr<VecLWEPlaintext> VecLWEEncryptionScheme::SetM(
//	const std::shared_ptr<VecLWEparams> params, const uint32_t m) const {
//
//	uint32_t q = params->Getq();
//	if (m > q)cout << "wrong in SetM m>q!";
//
//	VecLWEPlaintext plain;
//	vector<vector<uint16_t>> M(q);
//	for (long i = 0; i < q; i++)
//		M[i].resize(q);
//
//	for (long i = 0; i < q; i++)
//		M[i][(q + i - m) % q] = 1;
//
//	plain.SetM(M);
//	return make_shared<VecLWEPlaintext>(plain);
//
//};

void VecLWEEncryptionScheme_uint16::Decrypt(const std::shared_ptr<VecLWEparams_uint16> params,
	const std::shared_ptr<const VecLWESecretKey_uint16> sk,
	const std::shared_ptr<const VecLWECiphertext_uint16> ct,
	VecLWEPlaintext_uint16* result) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint32_t Q = params->GetQ();
	uint32_t t = params->Gett();
	vector<vector<uint16_t>> S = sk->GetS();
	vector<uint16_t> a = ct->Geta();
	vector<uint16_t> b = ct->Getb();

	vector<uint16_t> message(q);


	for (long i = 0; i < q; i++)
	{
		
		
			for (long k = 0; k < N; k++)
			{
				message[i] += (-S[i][k]) * a[k];
			}
			message[i] += b[i];
			message[i] = (short int)(round((double)message[i] * (double)t / (double)Q)) % t;
		
	}
	result->SetM(message);

};


void VecLWEEncryptionScheme_uint16::DecryptNoEncode(const std::shared_ptr<VecLWEparams_uint16> params,
	const std::shared_ptr<const VecLWESecretKey_uint16> sk,
	const std::shared_ptr<const VecLWECiphertext_uint16> ct,
	VecLWEPlaintext_uint16* result) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint32_t Q = params->GetQ();
	uint32_t t = params->Gett();
	vector<vector<uint16_t>> S = sk->GetS();
	vector<uint16_t> a = ct->Geta();
	vector<uint16_t> b = ct->Getb();

	vector<uint16_t> message(q);


	for (long i = 0; i < q; i++)
	{


		for (long k = 0; k < N; k++)
		{
			message[i] += (-S[i][k]) * a[k];
		}
		message[i] += b[i];
	//	message[i] = (short int)(round((double)message[i] * (double)t / (double)Q)) % t;

	}
	result->SetM(message);

};


//---------------------------------uint32---------------




std::shared_ptr<VecLWESecretKey_uint32> VecLWEEncryptionScheme_uint32::KeyGen(
	const std::shared_ptr<VecLWEparams_uint32> params) const {

	uint32_t q = params->Getq();
	uint32_t N = params->GetN();

	VecLWESecretKey_uint32 sec;
	vector<vector<uint32_t>> secret(q);
	for (uint32_t i = 0; i < q; i++)
	{
		secret[i].resize(N);
	}

	unsigned char* seed = new unsigned char[32];
	seed[0] = (unsigned)time(NULL);

	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];

	(*RNG_new_1).init(seed, 32);

	//	(*RNG_new_1).call_bytes(output_2, 32);

	for (long i = 0; i < q; i++)
		for (long j = 0; j < N; j++)
			secret[i][j] = sampler_New(5, 3, output_2, RNG_new_1);

	sec.SetS(secret);
	return make_shared<VecLWESecretKey_uint32>(sec);
}

std::shared_ptr<VecLWECiphertext_uint32> VecLWEEncryptionScheme_uint32::Encrypt(
	const std::shared_ptr<VecLWEparams_uint32> params,
	const std::shared_ptr<const VecLWESecretKey_uint32> sk,
	const std::shared_ptr<const VecLWEPlaintext_uint32> m) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint32_t t = params->Gett();
	uint32_t delta = params->Getdelta();

	vector<vector<uint32_t>> S = sk->GetS();
	vector<uint32_t> message = m->Getm();

	vector<uint32_t> encodem(q);
	for (long i = 0; i < q; i++)
		encodem[i] = delta * message[i];


	VecLWECiphertext_uint32 cipher;
	vector<uint32_t> a(N);
	vector<uint32_t> error(q);
	vector<uint32_t> b(q);

	//Generate vector a


	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	for (long i = 0; i < N; i++)
	{
		if (cnt == 0)
			(*RNG_new_1).call_bytes(output_2, 32);
		a[i] = (((uint32_t*)output_2)[cnt]);
		cnt = (cnt + 1) % 16;
	}

	cipher.Seta(a);

	//Compute b




	for (long i = 0; i < q; i++)
		error[i] = sampler_New(5, 3, output_2, RNG_new_1);



	for (long i = 0; i < q; i++)
	{
		for (long k = 0; k < N; k++)
		{
			b[i] += S[i][k] * a[k];

		}
		b[i] += error[i] + encodem[i];
	}

	cipher.Setb(b);

	return make_shared<VecLWECiphertext_uint32>(cipher);

};



//
//std::shared_ptr<VecLWEPlaintext> VecLWEEncryptionScheme::SetM(
//	const std::shared_ptr<VecLWEparams> params, const uint32_t m) const {
//
//	uint32_t q = params->Getq();
//	if (m > q)cout << "wrong in SetM m>q!";
//
//	VecLWEPlaintext plain;
//	vector<vector<uint16_t>> M(q);
//	for (long i = 0; i < q; i++)
//		M[i].resize(q);
//
//	for (long i = 0; i < q; i++)
//		M[i][(q + i - m) % q] = 1;
//
//	plain.SetM(M);
//	return make_shared<VecLWEPlaintext>(plain);
//
//};

void VecLWEEncryptionScheme_uint32::Decrypt(const std::shared_ptr<VecLWEparams_uint32> params,
	const std::shared_ptr<const VecLWESecretKey_uint32> sk,
	const std::shared_ptr<const VecLWECiphertext_uint32> ct,
	VecLWEPlaintext_uint32* result) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();
	uint32_t t = params->Gett();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<uint32_t> a = ct->Geta();
	vector<uint32_t> b = ct->Getb();

	vector<uint32_t> message(q);


	for (long i = 0; i < q; i++)
	{


		for (long k = 0; k < N; k++)
		{
			message[i] += (Q-S[i][k]) * a[k];
		}
		message[i] += b[i];
		message[i] = (short int)(round((double)message[i] * (double)t / (double)Q)) % t;

	}
	result->SetM(message);

};


void VecLWEEncryptionScheme_uint32::DecryptNoEncode(const std::shared_ptr<VecLWEparams_uint32> params,
	const std::shared_ptr<const VecLWESecretKey_uint32> sk,
	const std::shared_ptr<const VecLWECiphertext_uint32> ct,
	VecLWEPlaintext_uint32* result) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();
	uint32_t t = params->Gett();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<uint32_t> a = ct->Geta();
	vector<uint32_t> b = ct->Getb();

	vector<uint32_t> message(q);


	for (long i = 0; i < q; i++)
	{


		for (long k = 0; k < N; k++)
		{
			message[i] += (Q-S[i][k]) * a[k];
		}
		message[i] += b[i];
		//	message[i] = (short int)(round((double)message[i] * (double)t / (double)Q)) % t;

	}
	result->SetM(message);

};
