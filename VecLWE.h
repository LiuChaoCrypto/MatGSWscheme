#pragma once
#ifndef VECLWE_H
#define VECLWE_H



#include"VecLWEcore.h"


class VecLWEEncryptionScheme_uint16 {
public:
	VecLWEEncryptionScheme_uint16() {}


	std::shared_ptr<VecLWESecretKey_uint16> KeyGen(
		const std::shared_ptr<VecLWEparams_uint16> params) const;



	std::shared_ptr<VecLWECiphertext_uint16> Encrypt(
		const std::shared_ptr<VecLWEparams_uint16> params,
		const std::shared_ptr<const VecLWESecretKey_uint16> sk,
		const std::shared_ptr<const VecLWEPlaintext_uint16> m) const;


	void Decrypt(const std::shared_ptr<VecLWEparams_uint16> params,
		const std::shared_ptr<const VecLWESecretKey_uint16> sk,
		const std::shared_ptr<const VecLWECiphertext_uint16> ct,
		VecLWEPlaintext_uint16* result) const;

	void DecryptNoEncode(const std::shared_ptr<VecLWEparams_uint16> params,
		const std::shared_ptr<const VecLWESecretKey_uint16> sk,
		const std::shared_ptr<const VecLWECiphertext_uint16> ct,
		VecLWEPlaintext_uint16* result) const;


	std::shared_ptr<VecLWEPlaintext_uint16> SetM(
		const std::shared_ptr<VecLWEparams_uint16> params, const uint32_t m) const;



};





//----------------------------------uint32









class VecLWEEncryptionScheme_uint32 {
public:
	VecLWEEncryptionScheme_uint32() {}


	std::shared_ptr<VecLWESecretKey_uint32> KeyGen(
		const std::shared_ptr<VecLWEparams_uint32> params) const;



	std::shared_ptr<VecLWECiphertext_uint32> Encrypt(
		const std::shared_ptr<VecLWEparams_uint32> params,
		const std::shared_ptr<const VecLWESecretKey_uint32> sk,
		const std::shared_ptr<const VecLWEPlaintext_uint32> m) const;


	void Decrypt(const std::shared_ptr<VecLWEparams_uint32> params,
		const std::shared_ptr<const VecLWESecretKey_uint32> sk,
		const std::shared_ptr<const VecLWECiphertext_uint32> ct,
		VecLWEPlaintext_uint32* result) const;

	void DecryptNoEncode(const std::shared_ptr<VecLWEparams_uint32> params,
		const std::shared_ptr<const VecLWESecretKey_uint32> sk,
		const std::shared_ptr<const VecLWECiphertext_uint32> ct,
		VecLWEPlaintext_uint32* result) const;


	std::shared_ptr<VecLWEPlaintext_uint32> SetM(
		const std::shared_ptr<VecLWEparams_uint32> params, const uint32_t m) const;



};






#endif