#include"Bootstrapcore.h"
using namespace std;



std::shared_ptr<MatGSWCiphertext_uint32> BootstrapScheme_uint32::BootKeyGenOne(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<MatGSWSecretKey_uint32> secret,
	const uint32_t m) const {
	MatGSWEncryptionScheme_uint32 scheme;
	auto plain = scheme.SetPerM(params, m);
	auto cipher = scheme.Encrypt(params, secret, plain);
	return cipher;
};


std::shared_ptr<VecLWECiphertext_uint32> BootstrapScheme_uint32::BootstrappingOne(
	const std::shared_ptr<MatGSWparams_uint32> Matparams,
	const std::shared_ptr<VecLWEparams_uint32> Vecparams,
	const std::shared_ptr<MatGSWCiphertext_uint32> MatCipher,
	const std::shared_ptr<VecLWECiphertext_uint32> VecCipher) const {
	MatGSWEncryptionScheme_uint32 scheme;
	auto vec = scheme.MatVecMul(Matparams, Vecparams, MatCipher, VecCipher);
	return vec;
};



uint32_t roundingfunc(uint32_t input, uint32_t q, uint32_t t, uint64_t Q)
{
	uint32_t delta = floor((double)Q / (double)t);
	return (uint32_t)(round(((double)input / (double)q) * (double)t)) % t * delta;
}

uint32_t BooleanGate(uint32_t input, uint32_t q, uint32_t t, uint64_t Q, Boolean BL)
{	
	uint32_t delta = floor((double)Q / (double)t);
	uint32_t x = (uint32_t)(round(((double)input / (double)q) * (double)t)) % t;
	switch (BL)
	{
	case OR:
		if (x == 0) { return 0; }
		else { return delta; }
		break;
	case XOR:if (x == 1) { return delta; }
			else { return 0; }
		break;
	case AND:if (x == 2) { return delta; }
			else { return 0; }
		break;
	case NAND:if (x == 2) { return 0; }
			 else { return delta; }
		break;
	case NOR:if (x == 0) { return delta; }
			else { return 0; }
		break;
	case XNOR:if (x == 1) { return 0; }
			 else { return delta; }
		break;
	default: cout << "Not a correct Boolean"; return 0;
		break;
	}
}

std::shared_ptr<VecLWECiphertext_uint32> BootstrapScheme_uint32::Initialize(
	const std::shared_ptr<VecLWEparams_uint32> Vecparams,
	const uint32_t b
)const {
	uint32_t N = Vecparams->GetN();
	uint32_t q = Vecparams->Getq();
	uint32_t t = Vecparams->Gett();
	uint64_t Q = Vecparams->GetQ();

	VecLWECiphertext_uint32 veccipher;
	vector<uint32_t> vec_a(N);
	vector<uint32_t> vec_b(q);

	long integer;
	for (long i = 0; i < q; i++)
	{
		integer = b - i;
		if (integer < 0) {
			vec_b[i] = roundingfunc(q + integer, q, t, Q);
		}
		else {
			vec_b[i] = roundingfunc(integer, q, t, Q);
		}
	}
	veccipher.Seta(vec_a);
	veccipher.Setb(vec_b);
	return make_shared<VecLWECiphertext_uint32>(veccipher);

};


std::shared_ptr<VecLWECiphertext_uint32> BootstrapScheme_uint32::InitializeBool(
	const std::shared_ptr<VecLWEparams_uint32> Vecparams,
	const uint32_t b,
	Boolean BL
)const {
	uint32_t N = Vecparams->GetN();
	uint32_t q = Vecparams->Getq();
	uint32_t t = Vecparams->Gett();
	uint64_t Q = Vecparams->GetQ();

	VecLWECiphertext_uint32 veccipher;
	vector<uint32_t> vec_a(N);
	vector<uint32_t> vec_b(q);

	long integer;
	for (long i = 0; i < q; i++)
	{
		integer = b - i;
		if (integer < 0) {
			vec_b[i] = BooleanGate(q + integer, q, t, Q,BL);
		}
		else {
			vec_b[i] = BooleanGate(integer, q, t, Q,BL);
		}
	}
	veccipher.Seta(vec_a);
	veccipher.Setb(vec_b);
	return make_shared<VecLWECiphertext_uint32>(veccipher);
};


std::shared_ptr<LWECiphertext_uint32> BootstrapScheme_uint32::Bootstrapping(
	const std::shared_ptr<MatGSWparams_uint32> Matparams,
	const std::shared_ptr<VecLWEparams_uint32> Vecparams,
	const std::shared_ptr<LWECiphertext_uint32> InputLWEcipher,
	const std::shared_ptr<MatGSWSecretKey_uint32> MatSecret,
	const std::shared_ptr<LWESecretKey_uint32> InputLWESecret)const {

	uint32_t b = InputLWEcipher->Getb();
	vector<uint32_t> vec_a = InputLWEcipher->Geta();

	VecLWEEncryptionScheme_uint32 veclwescheme;

	VecLWESecretKey_uint32 vecsec;
	vecsec.SetS(MatSecret->GetS());

	vector<uint32_t> lwesec = InputLWESecret->Gets();

	BootstrapScheme_uint32 bootscheme;
	MatGSWEncryptionScheme_uint32 matschem;
	auto acc = bootscheme.Initialize(Vecparams, b);

	uint32_t N = Matparams->GetN();
	uint32_t q = Matparams->Getq();
	uint32_t n = Matparams->Getn();
	uint32_t N2 = Vecparams->GetN();
	uint32_t q2 = Vecparams->Getq();
	if ((N != N2) || (q != q2))cout << "\n Wrong! In bootstrapping, Mat and Vec parames not equal!";

	uint32_t a_sp;
	int l = ceil(log(q) / log(2));
	vector<uint32_t> a_sp_decomp(l);
	for (long i = 0; i < n; i++)
	{
		a_sp = (q - vec_a[i]) % q;
		a_sp_decomp = Ginverse_uint32(a_sp, l);

		for (long j = 0; j < l; j++)
		{
			if (a_sp_decomp[j] > 0)
			{
				uint32_t integer = ((uint32_t)pow(2, j) * lwesec[i]) % q;
				auto plian = matschem.SetPerM(Matparams, ((uint32_t)pow(2, j) * lwesec[i]) % q);
				auto matcipher = matschem.Encrypt(Matparams, MatSecret, plian);
				acc = matschem.MatVecMul(Matparams, Vecparams, matcipher, acc);
			}
		}
	}

	LWECiphertext_uint32 retu_cipher;
	retu_cipher.Seta(acc->Geta());
	retu_cipher.Setb((acc->Getb())[0]);
	return make_shared<LWECiphertext_uint32>(retu_cipher);
};


std::shared_ptr<LWECiphertext_uint32> BootstrapScheme_uint32::BootstrappingBool(
	const std::shared_ptr<MatGSWparams_uint32> Matparams,
	const std::shared_ptr<VecLWEparams_uint32> Vecparams,
	const std::shared_ptr<LWECiphertext_uint32> InputLWEcipher,
	const std::shared_ptr<MatGSWSecretKey_uint32> MatSecret,
	const std::shared_ptr<LWESecretKey_uint32> InputLWESecret,
	Boolean BL)const {
	uint32_t b = InputLWEcipher->Getb();
	vector<uint32_t> vec_a = InputLWEcipher->Geta();

	VecLWEEncryptionScheme_uint32 veclwescheme;

	VecLWESecretKey_uint32 vecsec;
	vecsec.SetS(MatSecret->GetS());

	vector<uint32_t> lwesec = InputLWESecret->Gets();

	BootstrapScheme_uint32 bootscheme;
	MatGSWEncryptionScheme_uint32 matschem;
	auto acc = bootscheme.InitializeBool(Vecparams, b,BL);

	uint32_t N = Matparams->GetN();
	uint32_t q = Matparams->Getq();
	uint32_t n = Matparams->Getn();
	uint32_t N2 = Vecparams->GetN();
	uint32_t q2 = Vecparams->Getq();
	if ((N != N2) || (q != q2))cout << "\n Wrong! In bootstrapping, Mat and Vec parames not equal!";

	uint32_t a_sp;
	int l = ceil(log(q) / log(2));
	vector<uint32_t> a_sp_decomp(l);
	for (long i = 0; i < n; i++)
	{
		a_sp = (q - vec_a[i]) % q;
		a_sp_decomp = Ginverse_uint32(a_sp, l);

		for (long j = 0; j < l; j++)
		{
			if (a_sp_decomp[j] > 0)
			{
				uint32_t integer = ((uint32_t)pow(2, j) * lwesec[i]) % q;
				auto plian = matschem.SetPerM(Matparams, ((uint32_t)pow(2, j) * lwesec[i]) % q);
				auto matcipher = matschem.Encrypt(Matparams, MatSecret, plian);
				acc = matschem.MatVecMul(Matparams, Vecparams, matcipher, acc);
			}
		}
	}
	LWECiphertext_uint32 retu_cipher;
	retu_cipher.Seta(acc->Geta());
	retu_cipher.Setb((acc->Getb())[0]);
	return make_shared<LWECiphertext_uint32>(retu_cipher);
};
