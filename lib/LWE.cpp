#include"LWE.h"
#include"random.h"



std::shared_ptr<LWESecretKey_uint32> LWEEncryptionScheme_uint32::KeyGen(
	const std::shared_ptr<LWEparams_uint32> params) const {

	uint32_t q = params->Getq();
	uint32_t n = params->Getn();

	LWESecretKey_uint32 sec;
	vector<uint32_t> secret(n);

	unsigned char* seed = new unsigned char[32];
	seed[0] = (unsigned)time(NULL);

	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];

	(*RNG_new_1).init(seed, 32);

	//	(*RNG_new_1).call_bytes(output_2, 32);
	short integer;
	for (long i = 0; i < n; i++) {
		integer = sampler_New(5, 3, output_2, RNG_new_1);
		if (integer < 0) { secret[i] = q + integer; }
		else { secret[i] = integer; }
	}

	sec.Sets(secret);
	return make_shared<LWESecretKey_uint32>(sec);
}

std::shared_ptr<LWECiphertext_uint32> LWEEncryptionScheme_uint32::Encrypt(
	const std::shared_ptr<LWEparams_uint32> params,
	const std::shared_ptr<const LWESecretKey_uint32> sk,
	const std::shared_ptr<const LWEPlaintext_uint32> m) const {

	uint32_t n = params->Getn();
	uint32_t q = params->Getq();
	uint32_t t = params->Gett();
	uint32_t delta = params->Getdelta();

	vector<uint32_t> S = sk->Gets();
	uint32_t message = m->Getm();
	if (message >= t)cout << "\n error: message >= t!" << endl;

	uint32_t encodem = delta * message;

	LWECiphertext_uint32 cipher;
	vector<uint32_t> a(n);
	uint32_t error;
	uint32_t b = 0;

	unsigned char* seed = new unsigned char[32];
	seed[0] = (unsigned)time(NULL);
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	for (long i = 0; i < n; i++)
	{
		if (cnt == 0)
			(*RNG_new_1).call_bytes(output_2, 32);
		a[i] = (((uint32_t*)output_2)[cnt]) % q;
		cnt = (cnt + 1) % 16;
	}

	cipher.Seta(a);

	short integer;
	integer = sampler_New(5, 3, output_2, RNG_new_1);
	if (integer < 0) { error = q + integer; }
	else {
		error = integer;
	}

	for (long i = 0; i < n; i++)
	{
		b = (b + (S[i] * a[i]) % q) % q;
	}

	b = ((b + error) % q + encodem) % q;

	cipher.Setb(b);

	return make_shared<LWECiphertext_uint32>(cipher);
};



void LWEEncryptionScheme_uint32::Decrypt(const std::shared_ptr<LWEparams_uint32> params,
	const std::shared_ptr<const LWESecretKey_uint32> sk,
	const std::shared_ptr<const LWECiphertext_uint32> ct,
	LWEPlaintext_uint32* result) const {

	uint32_t n = params->Getn();
	uint64_t q = params->Getq();
	uint32_t t = params->Gett();
	vector<uint32_t> S = sk->Gets();
	vector<uint32_t> a = ct->Geta();
	uint32_t b = ct->Getb();

	uint32_t message = 0;

	long integer;
	for (long i = 0; i < n; i++)
	{
		message = (message + (S[i] * a[i]) % q) % q;
	}
	integer = b - message;
	if (integer < 0) { message = q + integer; }
	else { message = integer % q; }

	message = (short int)(round((double)message * (double)t / (double)q)) % t;
	result->Setm(message);
};


std::shared_ptr <LWECiphertext_uint32>  LWEEncryptionScheme_uint32::LWEadd(
	const std::shared_ptr<LWEparams_uint32> params,
	const std::shared_ptr<const LWECiphertext_uint32> cipher1,
	const std::shared_ptr<const LWECiphertext_uint32> cipher2) const {
	
	uint32_t n = params->Getn();
	uint64_t q = params->Getq();
	uint32_t t = params->Gett();
	vector<uint32_t> a1 = cipher1->Geta();
	vector<uint32_t> a2 = cipher2->Geta();
	uint32_t b1 = cipher1->Getb();
	uint32_t b2 = cipher2->Getb();

	vector<uint32_t> a3;
	a3.resize(n);
	uint32_t b3;
	for (uint32_t i=0; i < n; i++)
	{
		a3[i] = (a1[i] + a2[i])%q;
	}
	b3 = (b1 + b2)%q;

	LWECiphertext_uint32 recipher;
	recipher.Seta(a3);
	recipher.Setb(b3);
	return make_shared<LWECiphertext_uint32>(recipher);
}
