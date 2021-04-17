
#ifndef LWECORE_H
#define LWECORE_H

#include <string>
#include <vector>
#include<stdint.h>
#include<stdio.h>
#include <iostream>
#include"Head.h"
using namespace std;

class LWEparams_uint16 {
public:
	LWEparams_uint16() :m_n(0), m_q(0), m_sigma(0), m_t(0), m_delta(0) {}
	explicit LWEparams_uint16(uint32_t t_n, uint32_t t_q, float t_sigma, uint32_t t_t)
		: m_n(t_n), m_q(t_q), m_sigma(t_sigma), m_t(t_t) {
		m_delta = floor((double)m_q / (double)m_t);
	}

	uint32_t Getn() const { return m_n; }
	uint32_t Getq() const { return m_q; }
	float Getsigma() const { return m_sigma; }
	uint32_t Gett() const { return m_t; }
	uint32_t Getdelta() const { return m_delta; }

private:
	uint32_t m_n;
	uint32_t m_q;
	float m_sigma;
	uint32_t m_t;//pliantext space
	uint32_t m_delta;// Q/t
};

class LWECiphertext_uint16 {
public:
	LWECiphertext_uint16() {}
	explicit LWECiphertext_uint16(const vector<uint16_t>& a, const uint16_t b) : vec_a(a), b(b) {}

	const vector<uint16_t>& Geta() const { return vec_a; }
	const uint16_t Getb() const { return b; }
	void Seta(const vector<uint16_t>& a) { vec_a = a; }
	void Setb(const uint16_t d) { b = d; }
private:
	vector<uint16_t> vec_a;
	uint16_t b;
};

class LWESecretKey_uint16 {
public:
	LWESecretKey_uint16() {}
	explicit LWESecretKey_uint16(const vector<uint16_t>& s) : vec_s(s) {}
	const LWESecretKey_uint16& operator=(const LWESecretKey_uint16& rhs) {
		this->vec_s = rhs.vec_s;
		return *this;
	}
	const vector<uint16_t>& Gets() const { return vec_s; }
	void Sets(const vector<uint16_t>& b) { vec_s = b; }
private:
	vector<uint16_t> vec_s;
};

class LWEPlaintext_uint16 {
public:
	LWEPlaintext_uint16() {}
	explicit LWEPlaintext_uint16(const uint16_t& b) : m(b) {}
	const uint16_t Getm() const { return m; }
	void Setm(const uint16_t b) { m = b; }
private:
	uint16_t m;
};


//-------------------------------------------uint32----------------



class LWEparams_uint32 {
public:
	LWEparams_uint32() :m_n(0), m_q(0), m_sigma(0), m_t(0), m_delta(0) {}
	explicit LWEparams_uint32(uint32_t t_n, uint64_t t_q, float t_sigma, uint32_t t_t)
		: m_n(t_n), m_q(t_q), m_sigma(t_sigma), m_t(t_t) {
		m_delta = floor((double)m_q / (double)m_t);
	}

	uint32_t Getn() const { return m_n; }
	uint64_t Getq() const { return m_q; }
	float Getsigma() const { return m_sigma; }
	uint32_t Gett() const { return m_t; }
	uint32_t Getdelta() const { return m_delta; }

private:
	uint32_t m_n;
	uint64_t m_q;
	float m_sigma;
	uint32_t m_t;//pliantext space
	uint32_t m_delta;// Q/t
};




class LWECiphertext_uint32 {
public:
	LWECiphertext_uint32() {}
	explicit LWECiphertext_uint32(const vector<uint32_t>& a, const uint32_t b) : vec_a(a), b(b) {}

	const vector<uint32_t>& Geta() const { return vec_a; }
	const uint32_t Getb() const { return b; }
	void Seta(const vector<uint32_t>& a) { vec_a = a; }
	void Setb(const uint32_t d) { b = d; }
private:
	vector<uint32_t> vec_a;
	uint32_t b;
};

class LWESecretKey_uint32 {
public:
	LWESecretKey_uint32() {}
	explicit LWESecretKey_uint32(const vector<uint32_t>& s) : vec_s(s) {}
	const LWESecretKey_uint32& operator=(const LWESecretKey_uint32& rhs) {
		this->vec_s = rhs.vec_s;
		return *this;
	}
	const vector<uint32_t>& Gets() const { return vec_s; }
	void Sets(const vector<uint32_t>& b) { vec_s = b; }
private:
	vector<uint32_t> vec_s;
};

class LWEPlaintext_uint32 {
public:
	LWEPlaintext_uint32() {}
	explicit LWEPlaintext_uint32(const uint32_t& b) : m(b) {}
	const uint32_t Getm() const { return m; }
	void Setm(const uint32_t b) { m = b; }
private:
	uint32_t m;
};

#endif
