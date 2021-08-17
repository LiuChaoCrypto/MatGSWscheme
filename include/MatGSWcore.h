#ifndef MATGSWCORE_H
#define MATGSWCORE_H

#include <string>
#include <vector>
#include<stdint.h>
#include<stdio.h>
#include <iostream>
#include"Head.h"
using namespace std;


class MatGSWparams_uint32 {
public:
	MatGSWparams_uint32() :m_N(0), m_Q(0), m_sigma(0), m_q(0), m_l(0), m_n(0) {}

	explicit MatGSWparams_uint32(uint32_t t_N, uint64_t t_Q, float t_sigma, uint32_t t_q, uint32_t t_n)
		: m_N(t_N), m_Q(t_Q), m_sigma(t_sigma), m_q(t_q), m_n(t_n) {
		if (t_Q != pow(2, 32))cout << "wrong Q!=2^32";
		m_l = log(m_Q) / log(2);
	}

	uint32_t GetN() const { return m_N; }
	uint64_t GetQ() const { return m_Q; }
	float Getsigma() const { return m_sigma; }
	uint32_t Getq() const { return m_q; }
	uint32_t Getl() const { return m_l; }
	uint32_t Getn() const { return m_n; }

private:
	uint32_t m_N;
	uint64_t m_Q;
	float m_sigma;
	uint32_t m_q;
	uint32_t m_l;
	uint32_t m_n;
};




class MatGSWCiphertext_uint32 {
public:
	MatGSWCiphertext_uint32() {}
	explicit MatGSWCiphertext_uint32(const vector<vector<uint32_t>>& a, const vector<vector<uint32_t>>& b) : mat_A(a), mat_B(b) {}

	const vector<vector<uint32_t>>& GetA() const { return mat_A; }

	const vector<vector<uint32_t>>& GetB() const { return mat_B; }

	void SetA(const vector<vector<uint32_t>>& a) { mat_A = a; }
	void SetB(const vector<vector<uint32_t>>& b) { mat_B = b; }
private:
	vector<vector<uint32_t>> mat_A;
	vector<vector<uint32_t>> mat_B;
};

class MatGSWSecretKey_uint32 {
public:
	MatGSWSecretKey_uint32() {}

	explicit MatGSWSecretKey_uint32(const vector<vector<uint32_t>>& s) : mat_S(s) {}
	const MatGSWSecretKey_uint32& operator=(const MatGSWSecretKey_uint32& rhs) {
		this->mat_S = rhs.mat_S;
		return *this;
	}
	const vector<vector<uint32_t>>& GetS() const { return mat_S; }
	void SetS(const vector<vector<uint32_t>>& b) { mat_S = b; }
private:
	vector<vector<uint32_t>> mat_S;
};

class MatGSWPlaintext_uint32 {
public:
	MatGSWPlaintext_uint32() {}

	explicit MatGSWPlaintext_uint32(const vector<vector<uint32_t>>& m) : mat_M(m) {}

	const vector<vector<uint32_t>>& GetM() const { return mat_M; }

	void SetM(const vector<vector<uint32_t>>& b) { mat_M = b; }
private:
	vector<vector<uint32_t>> mat_M;
};


#endif
