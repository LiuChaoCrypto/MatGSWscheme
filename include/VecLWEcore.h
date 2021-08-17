#pragma once
#ifndef VECLWECORE_H
#define VECLWECORE_H

#include <string>
#include <vector>
#include<stdint.h>
#include<stdio.h>
#include <iostream>
#include"Head.h"
using namespace std;

class VecLWEparams_uint32 {
public:
	VecLWEparams_uint32() :m_N(0), m_Q(0), m_sigma(0), m_q(0), m_l(0), m_t(0), m_delta(0) {}

	explicit VecLWEparams_uint32(uint32_t t_N, uint64_t t_Q, float t_sigma, uint32_t t_q, uint32_t t_t)
		: m_N(t_N), m_Q(t_Q), m_sigma(t_sigma), m_q(t_q), m_t(t_t) {
		if (t_Q != pow(2, 32))cout << "wrong Q!=2^32";
		m_l = log(m_Q) / log(2);
		m_delta = floor((double)m_Q / (double)m_t);
	}

	uint32_t GetN() const { return m_N; }
	uint64_t GetQ() const { return m_Q; }
	float Getsigma() const { return m_sigma; }
	uint32_t Getq() const { return m_q; }
	uint32_t Getl() const { return m_l; }
	uint32_t Gett() const { return m_t; }
	uint32_t Getdelta() const { return m_delta; }

private:
	uint32_t m_N;
	uint64_t m_Q;
	float m_sigma;
	uint32_t m_q;
	uint32_t m_l;
	uint32_t m_t;//pliantext space
	uint32_t m_delta;// Q/t
};

class VecLWECiphertext_uint32 {
public:
	VecLWECiphertext_uint32() {}
	explicit VecLWECiphertext_uint32(const vector<uint32_t>& a, const vector<uint32_t>& b) : vec_a(a), vec_b(b) {}

	const vector<uint32_t>& Geta() const { return vec_a; }

	const vector<uint32_t>& Getb() const { return vec_b; }

	void Seta(const vector<uint32_t>& a) { vec_a = a; }
	void Setb(const vector<uint32_t>& b) { vec_b = b; }
private:
	vector<uint32_t> vec_a;
	vector<uint32_t> vec_b;
};

class VecLWESecretKey_uint32 {
public:
	VecLWESecretKey_uint32() {}

	explicit VecLWESecretKey_uint32(const vector<vector<uint32_t>>& s) : mat_S(s) {}

	const VecLWESecretKey_uint32& operator=(const VecLWESecretKey_uint32& rhs) {
		this->mat_S = rhs.mat_S;
		return *this;
	}

	const vector<vector<uint32_t>>& GetS() const { return mat_S; }

	void SetS(const vector<vector<uint32_t>>& b) { mat_S = b; }
private:
	vector<vector<uint32_t>> mat_S;
};

class VecLWEPlaintext_uint32 {
public:
	VecLWEPlaintext_uint32() {}

	explicit VecLWEPlaintext_uint32(const vector<uint32_t>& m) : vec_m(m) {}

	const vector<uint32_t>& Getm() const { return vec_m; }

	void SetM(const vector<uint32_t>& b) { vec_m = b; }
private:
	vector<uint32_t> vec_m;
};
#endif // !VECLWECORE_H
