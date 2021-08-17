#include"MatGSW.h"
#include"random.h"
#include"TestTime.h"


std::shared_ptr<MatGSWSecretKey_uint32> MatGSWEncryptionScheme_uint32::KeyGen(
	const std::shared_ptr<MatGSWparams_uint32> params) const {

	uint32_t q = params->Getq();
	uint32_t N = params->GetN();

	MatGSWSecretKey_uint32 sec;
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
	for (long i = 0; i < q; i++)
		for (long j = 0; j < N; j++)
			secret[i][j] = sampler_New(5, 3, output_2, RNG_new_1);

	sec.SetS(secret);
	return make_shared<MatGSWSecretKey_uint32>(sec);
}

void MatGSWEncryptionScheme_uint32::Encrypt_Fast_TEST(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
	const std::shared_ptr<const MatGSWPlaintext_uint32> m,double &onetime) const {
	double processingTime(0.0);
	TimeVar t;
    uint64_t Q = params->GetQ();
	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<vector<uint32_t>> M = m->GetM();

	vector<vector<uint32_t>> MSG(1);//(-MS||M)G
	for (long i = 0; i < 1; i++)
		MSG[i].resize((N + q) * l);

	vector<vector<uint32_t>> B(1);
	for (long i = 0; i < 1; i++)
	{
		B[i].resize(1);
	}
	vector<vector<uint32_t>> E(1);
	for (uint32_t i = 0; i < 1; i++)
	{
		E[i].resize(1);
	}

	MatGSWCiphertext_uint32 cipher;

	//Generate matrix A
	vector<vector<uint32_t>> A(N);
	for (long i = 0; i < N; i++)
		A[i].resize(1);

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	for (long i = 0; i < N; i++)
	{
		for (long j = 0; j < 1; j++)
		{
			if (cnt == 0)
				(*RNG_new_1).call_bytes(output_2, 32);
			A[i][j] = (((uint32_t*)output_2)[cnt]);
			cnt = (cnt + 1) % 16;
		}
	}
	cipher.SetA(A);

	//Compute B

	for (long i = 0; i < 1; i++) {
		for (long j = 0; j <1; j++)
			E[i][j] = sampler_New(5, 3, output_2, RNG_new_1);
	}
	
	cout << "\n Generat B";
	for (long i = 0; i < 1; i++) {
		TIC(t);
		for (long j = 0; j <1; j++) {
			for (long k = 0; k < N; k++)
			{
				B[i][j] += S[i][k] * A[k][j];
			}
			B[i][j] += E[i][j] + MSG[i][j];
		}
		processingTime = TOC_US(t);
		std::cout
			<< "\n In Keygen for once vector product, it takes: "
			<< processingTime << "us" << std::endl;
	}
	onetime = processingTime * q*(N+q)*l/1000;

	cout << "\nGenerate one MatGSW ciphertext time is " << onetime << "ms";
	cipher.SetB(B);
};


std::shared_ptr<MatGSWCiphertext_uint32> MatGSWEncryptionScheme_uint32::Encrypt_Fast(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
	const std::shared_ptr<const MatGSWPlaintext_uint32> m) const {

	uint64_t Q = params->GetQ();
	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<vector<uint32_t>> M = m->GetM();
	vector<vector<uint32_t>> G(N + q);
	for (long i = 0; i < N + q; i++)
		G[i].resize((N + q) * l);

	vector<vector<uint32_t>> MSG(q);//(-MS||M)G
	for (long i = 0; i < q; i++)
		MSG[i].resize((N + q) * l);

	long int_message = 0;
	for (long i = 0; i < q; i++)
	{
		if (M[0][i] == 1) {
			int_message = (q - i) % q;
			break;
		}
	}

	vector<vector<uint32_t>> MS(q);//-MS
	for (long i = 0; i < q; i++)
		MS[i].resize(N);
	cout << "\n Generate MS";
	for (long i = 0; i < q; i++)
		for (long j = 0; j < N; j++)
			MS[i][j] = (Q - S[(q + i - int_message) % q][j]) % Q;

	cout << "\n Generate MS";
	for (long i = 0; i < q; i++)
		for (long j = 0; j < N * l; j += l)
			for (long k = 0; k < l; k++)
			{
				MSG[i][j + k] = (MS[i][j / l] << k);
			}
	for (long i = 0; i < q; i++)
		for (long k = 0; k < l; k++)
		{
			MSG[(int_message + i) % q][i * l + k + N * l] = (1 << k);
		}
	vector<vector<uint32_t>> B(q);
	for (long i = 0; i < q; i++)
	{
		B[i].resize((N + q) * l);
	}
	vector<vector<uint32_t>> E(q);
	for (uint32_t i = 0; i < q; i++)
	{
		E[i].resize((N + q) * l);
	}

	MatGSWCiphertext_uint32 cipher;


	//Generate matrix A
	vector<vector<uint32_t>> A(N);
	for (long i = 0; i < N; i++)
		A[i].resize((N + q) * l);
	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	cout << "\n Generate A";
	for (long i = 0; i < N; i++)
	{
		for (long j = 0; j < (N + q) * l; j++)
		{
			if (cnt == 0)
				(*RNG_new_1).call_bytes(output_2, 32);
			A[i][j] = (((uint32_t*)output_2)[cnt]);
			cnt = (cnt + 1) % 16;
		}
	}
	cipher.SetA(A);

	//Compute B

	for (long i = 0; i < q; i++) {
		for (long j = 0; j < (N + q) * l; j++)
			E[i][j] = sampler_New(5, 3, output_2, RNG_new_1);
	}

	TimeVar t;
	double processingTime(0.0);

	cout << "\n Generat B";
	for (long i = 0; i < q; i++) {
		TIC(t);
		for (long j = 0; j < (N + q) * l; j++) {
			for (long k = 0; k < N; k++)
			{
				B[i][j] += S[i][k] * A[k][j];
			}
			B[i][j] += E[i][j] + MSG[i][j];
		}
		processingTime = TOC(t);
		std::cout
			<< "\nEvery q it is: "
			<< processingTime << "ms" << std::endl;
	}
	cipher.SetB(B);

	return make_shared<MatGSWCiphertext_uint32>(cipher);

};




std::shared_ptr<MatGSWCiphertext_uint32> MatGSWEncryptionScheme_uint32::Encrypt(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
	const std::shared_ptr<const MatGSWPlaintext_uint32> m) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<vector<uint32_t>> M = m->GetM();
	vector<vector<uint32_t>> G(N + q);
	for (long i = 0; i < N + q; i++)
		G[i].resize((N + q) * l);
	vector<vector<uint32_t>> B(q);
	for (long i = 0; i < q; i++)
	{
		B[i].resize((N + q) * l);
	}
	vector<vector<uint32_t>> E(q);
	for (uint32_t i = 0; i < q; i++)
	{
		E[i].resize((N + q) * l);
	}

	vector<vector<uint32_t>> MS(q);//(-MS||M)
	for (long i = 0; i < q; i++)
		MS[i].resize(N + q);

	vector<vector<uint32_t>> MSG(q);//(-MS||M)G
	for (long i = 0; i < q; i++)
		MSG[i].resize((N + q) * l);

	vector<uint32_t> g(l);
	for (long i = 0; i < l; i++)
		g[i] = (1 << i);

	for (long i = 0; i < N + q; i++)
		for (long j = i * l; j < (i + 1) * l; j++)
			G[i][j] = g[j - i * l];

	MatGSWCiphertext_uint32 cipher;


	//Generate matrix A
	vector<vector<uint32_t>> A(N);
	for (long i = 0; i < N; i++)
		A[i].resize((N + q) * l);

	unsigned char* seed = new unsigned char[32];
	RNG_New* RNG_new_1 = new RNG_New();
	unsigned char* output_2 = new unsigned char[32];
	(*RNG_new_1).init(seed, 32);
	short cnt = 0;
	for (long i = 0; i < N; i++)
	{
		for (long j = 0; j < (N + q) * l; j++)
		{
			if (cnt == 0)
				(*RNG_new_1).call_bytes(output_2, 32);
			A[i][j] = (((uint32_t*)output_2)[cnt]);
			cnt = (cnt + 1) % 16;
		}
	}
	cipher.SetA(A);

	//Compute B

	for (long i = 0; i < q; i++) {
		for (long j = 0; j < (N + q) * l; j++)
			E[i][j] = sampler_New(5, 3, output_2, RNG_new_1);
	}
	for (long i = 0; i < q; i++)
		for (long j = 0; j < N; j++)
			for (long k = 0; k < q; k++)
				MS[i][j] += (Q-M[i][k]) * S[k][j];

	for (long i = 0; i < q; i++)
		for (long j = N; j < N + q; j++)
			MS[i][j] = M[i][j - N];


	TimeVar t;
	double processingTime(0.0);


	for (long i = 0; i < q; i++) {
		for (long j = 0; j < (N + q) * l; j++)
			for (long k = 0; k < N + q; k++)
				MSG[i][j] += MS[i][k] * G[k][j];
	}
	
	for (long i = 0; i < q; i++) {
		for (long j = 0; j < (N + q) * l; j++) {
			for (long k = 0; k < N; k++)
			{
				B[i][j] += S[i][k] * A[k][j];
			}
			B[i][j] += E[i][j] + MSG[i][j];
		}
	}
	cipher.SetB(B);

	return make_shared<MatGSWCiphertext_uint32>(cipher);

};


std::shared_ptr<MatGSWPlaintext_uint32> MatGSWEncryptionScheme_uint32::SetPerM(
	const std::shared_ptr<MatGSWparams_uint32> params, const uint32_t m) const {

	uint32_t q = params->Getq();
	if (m > q)cout << "wrong in SetM m>q!";

	MatGSWPlaintext_uint32 plain;
	vector<vector<uint32_t>> M(q);
	for (long i = 0; i < q; i++)
		M[i].resize(q);

	for (long i = 0; i < q; i++)
		M[i][(q + i - m) % q] = 1;

	plain.SetM(M);
	return make_shared<MatGSWPlaintext_uint32>(plain);

};

void MatGSWEncryptionScheme_uint32::Decrypt(const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
	const std::shared_ptr<const MatGSWCiphertext_uint32> ct,
	MatGSWPlaintext_uint32* result) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();
	vector<vector<uint32_t>> S = sk->GetS();
	vector<vector<uint32_t>> A = ct->GetA();
	vector<vector<uint32_t>> B = ct->GetB();

	vector<vector<uint32_t>> M(q);
	for (long i = 0; i < q; i++)
		M[i].resize(q);

	for (long i = 0; i < q; i++)
	{
		for (long j = 0; j < q; j++)
		{
			for (long k = 0; k < N; k++)
			{
				M[i][j] += (Q-S[i][k]) * A[k][N * l + (j + 1) * l - 2];
			}
			M[i][j] += B[i][N * l + (j + 1) * l - 2];
			M[i][j] = (short int)(round((double)M[i][j] * (double)4 / (double)Q)) % 2;
		}
	}
	result->SetM(M);
};


std::shared_ptr<MatGSWCiphertext_uint32> MatGSWEncryptionScheme_uint32::MatAdd(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
	const std::shared_ptr<const MatGSWCiphertext_uint32> cipher2) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();

	MatGSWCiphertext_uint32 cipher;

	vector<vector<uint32_t>> A1 = cipher1->GetA();
	vector<vector<uint32_t>> B1 = cipher1->GetB();
	vector<vector<uint32_t>> A2 = cipher2->GetA();
	vector<vector<uint32_t>> B2 = cipher2->GetB();

	for (long i = 0; i < N; i++)
		for (long j = 0; j < (N + q) * l; j++)
		{
			A1[i][j] += A2[i][j];
		}
	for (long i = 0; i < q; i++)
		for (long j = 0; j < (N + q) * l; j++)
		{
			B1[i][j] += B2[i][j];
		}
	cipher.SetA(A1);
	cipher.SetB(B1);
	return make_shared<MatGSWCiphertext_uint32>(cipher);
};

vector<uint32_t> Ginverse_uint32(uint32_t number, long l) {

	uint32_t testnumber = number, inter;
	vector<uint32_t>  inv(l);
	for (long i = 0; i < l; i++)
	{
		inter = (testnumber >> 1);

		inv[i] = testnumber - (inter << 1);
		testnumber = inter;
	}
	return inv;
};


vector<uint32_t> vecGinverse_uint32(vector<uint32_t> vec_number, long row, long l) {

	vector<uint32_t> vecinv(l * row);
	vector<uint32_t> inv(l);
	for (long i = 0; i < row; i++)
	{
		inv = Ginverse_uint32(vec_number[i], l);
		copy(inv.begin(), inv.end(), vecinv.begin() + i * l);
	}
	return vecinv;
};

vector<vector<uint32_t>> matGinverse_uint32(vector<vector<uint32_t>> mat_number, long row, long colum, long l) {

	vector<vector<uint32_t>> matinv(colum);
	vector<vector<uint32_t>> mat_number_T(colum);

	for (long i = 0; i < colum; i++)
		mat_number_T[i].resize(row);

	for (long i = 0; i < row; i++)
		for (long j = 0; j < colum; j++)
			mat_number_T[j][i] = mat_number[i][j];

	vector<uint32_t> vecinv(l * row);
	for (long i = 0; i < colum; i++)
		matinv[i].resize(l * row);
	for (long i = 0; i < colum; i++)
	{
		matinv[i] = vecGinverse_uint32(mat_number_T[i], row, l);
	}
	return matinv;
};




std::shared_ptr<MatGSWCiphertext_uint32> MatGSWEncryptionScheme_uint32::MatMul(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
	const std::shared_ptr<const MatGSWCiphertext_uint32> cipher2) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();

	MatGSWCiphertext_uint32 cipher;

	vector<vector<uint32_t>> A1 = cipher1->GetA();
	vector<vector<uint32_t>> B1 = cipher1->GetB();
	vector<vector<uint32_t>> A2 = cipher2->GetA();
	vector<vector<uint32_t>> B2 = cipher2->GetB();

	vector<vector<uint32_t>> C2(N + q);
	for (long i = 0; i < N + q; i++)
		C2[i].resize((N + q) * l);

	copy(A2.begin(), A2.end(), C2.begin());
	copy(B2.begin(), B2.end(), C2.begin() + N);


	vector<vector<uint32_t>> A(N);
	for (long i = 0; i < N; i++)
		A[i].resize((N + q) * l);
	vector<vector<uint32_t>> B(q);
	for (long i = 0; i < q; i++)
		B[i].resize((N + q) * l);

	vector<vector<uint32_t>> C2inverse = matGinverse_uint32(C2, N + q, (N + q) * l, l);

	for (long i = 0; i < N; i++)
		for (long j = 0; j < (N + q) * l; j++)
			for (long k = 0; k < (N + q) * l; k++)
				A[i][j] += A1[i][k] * C2inverse[j][k];
	for (long i = 0; i < q; i++)
		for (long j = 0; j < (N + q) * l; j++)
			for (long k = 0; k < (N + q) * l; k++)
				B[i][j] += B1[i][k] * C2inverse[j][k];

	cipher.SetA(A);
	cipher.SetB(B);
	return make_shared<MatGSWCiphertext_uint32>(cipher);
};



std::shared_ptr<VecLWECiphertext_uint32> MatGSWEncryptionScheme_uint32::MatVecMul(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<VecLWEparams_uint32> params2,
	const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
	const std::shared_ptr<const VecLWECiphertext_uint32> cipher2) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();

	uint32_t N2 = params2->GetN();
	uint32_t q2 = params2->Getq();
	uint32_t l2 = params2->Getl();
	uint64_t Q2 = params2->GetQ();

	if ((N != N2) || (q != q2) || (l != l2) || (Q != Q2))cout << "\nwrong in MatVecMul, MatGSW VecLWE parames not equal\n";

	VecLWECiphertext_uint32 cipher;

	vector<vector<uint32_t>> A1 = cipher1->GetA();
	vector<vector<uint32_t>> B1 = cipher1->GetB();
	vector<uint32_t> a2 = cipher2->Geta();
	vector<uint32_t> b2 = cipher2->Getb();

	vector<uint32_t> C2(N + q);

	copy(a2.begin(), a2.end(), C2.begin());
	copy(b2.begin(), b2.end(), C2.begin() + N);

	vector<uint32_t> a(N);
	vector<uint32_t> b(q);

	vector<uint32_t> C2inverse = vecGinverse_uint32(C2, N + q, l);

	for (long i = 0; i < N; i++)
		for (long k = 0; k < (N + q) * l; k++)
			a[i] += A1[i][k] * C2inverse[k];
	for (long i = 0; i < q; i++)
		for (long k = 0; k < (N + q) * l; k++)
			b[i] += B1[i][k] * C2inverse[k];

	cipher.Seta(a);
	cipher.Setb(b);
	return make_shared<VecLWECiphertext_uint32>(cipher);
};

uint32_t MatGSWEncryptionScheme_uint32::VecVecMul(
	const std::shared_ptr<MatGSWparams_uint32> params,
	const std::shared_ptr<VecLWEparams_uint32> params2,
	const vector<uint32_t> cipher1,
	const std::shared_ptr<const VecLWECiphertext_uint32> cipher2) const {

	uint32_t N = params->GetN();
	uint32_t q = params->Getq();
	uint32_t l = params->Getl();
	uint64_t Q = params->GetQ();

	uint32_t N2 = params2->GetN();
	uint32_t q2 = params2->Getq();
	uint32_t l2 = params2->Getl();
	uint64_t Q2 = params2->GetQ();

	if ((N != N2) || (q != q2) || (l != l2) || (Q != Q2))cout << "\nwrong in MatVecMul, MatGSW VecLWE parames not equal\n";

	vector<uint32_t> a2 = cipher2->Geta();
	vector<uint32_t> b2 = cipher2->Getb();

	vector<uint32_t> C2(N + q);

	copy(a2.begin(), a2.end(), C2.begin());
	copy(b2.begin(), b2.end(), C2.begin() + N);

	uint32_t a0 = 0;

	vector<uint32_t> C2inverse = vecGinverse_uint32(C2, N + q, l);


	for (long k = 0; k < (N + q) * l; k++)
		a0 += cipher1[k] * C2inverse[k];
	return a0;
};
