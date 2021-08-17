#pragma once
#pragma once
#ifndef LWE_H
#define LWE_H

#include"LWEcore.h"


class LWEEncryptionScheme_uint32 {
public:
	LWEEncryptionScheme_uint32() {}

    std::shared_ptr<LWESecretKey_uint32> KeyGen(
		const std::shared_ptr<LWEparams_uint32> params) const;

	std::shared_ptr<LWECiphertext_uint32> Encrypt(
		const std::shared_ptr<LWEparams_uint32> params,
		const std::shared_ptr<const LWESecretKey_uint32> sk,
		const std::shared_ptr<const LWEPlaintext_uint32> m) const;

	void Decrypt(const std::shared_ptr<LWEparams_uint32> params,
		const std::shared_ptr<const LWESecretKey_uint32> sk,
		const std::shared_ptr<const LWECiphertext_uint32> ct,
		LWEPlaintext_uint32* result) const;
	
    std::shared_ptr<LWECiphertext_uint32> LWEadd(
		const std::shared_ptr<LWEparams_uint32> params,
		const std::shared_ptr<const LWECiphertext_uint32> cipher1,
		const std::shared_ptr<const LWECiphertext_uint32> cipehr2
	)const;
};
#endif
