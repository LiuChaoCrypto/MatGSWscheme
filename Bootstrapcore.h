#pragma once

#ifndef BOOTSTRAPCORE_H
#define BOOTSTRAPCORE_H

#include"LWE.h"
#include"LWEcore.h"
#include"MatGSW.h"
#include"MatGSWcore.h"
#include"random.h"
#include"VecLWE.h"
#include"VecLWEcore.h"
#include"hash.h"
#include<math.h>
using namespace std;

enum Boolean { OR,XOR, AND,NAND,NOR,XNOR };

class BootstrapScheme_uint16 {
public:
	BootstrapScheme_uint16() {}

	std::shared_ptr<MatGSWCiphertext_uint16> BootKeyGenOne(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<MatGSWSecretKey_uint16> secret,
		const uint16_t m) const;

	std::shared_ptr<VecLWECiphertext_uint16> BootstrappingOne(
		const std::shared_ptr<MatGSWparams_uint16> Matparams,
		const std::shared_ptr<VecLWEparams_uint16> Vecparams,
		const std::shared_ptr<MatGSWCiphertext_uint16> MatCipher,
		const std::shared_ptr<VecLWECiphertext_uint16> VecCipher) const;
	
	std::shared_ptr<VecLWECiphertext_uint16> Initialize(
		const std::shared_ptr<VecLWEparams_uint16> Vecparams,
		const uint16_t b
	)const;

	std::shared_ptr<LWECiphertext_uint16> Bootstrapping(
		const std::shared_ptr<MatGSWparams_uint16> Matparams,
		const std::shared_ptr<VecLWEparams_uint16> Vecparams,
		const std::shared_ptr<LWECiphertext_uint16> InputLWEcipher,
		const std::shared_ptr<MatGSWSecretKey_uint16> MatSecret,
		const std::shared_ptr<LWESecretKey_uint16> InputLWESecret
	)const;
};


uint32_t roundingfunc(uint32_t input, uint32_t q, uint32_t t, uint32_t Q);

uint32_t BooleanGate(uint32_t input, uint32_t q, uint32_t t, uint32_t Q, Boolean BL);


//----------------------------uint32

class BootstrapScheme_uint32 {
public:
	BootstrapScheme_uint32() {}

	std::shared_ptr<MatGSWCiphertext_uint32> BootKeyGenOne(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<MatGSWSecretKey_uint32> secret,
		const uint32_t m) const;

	std::shared_ptr<VecLWECiphertext_uint32> BootstrappingOne(
		const std::shared_ptr<MatGSWparams_uint32> Matparams,
		const std::shared_ptr<VecLWEparams_uint32> Vecparams,
		const std::shared_ptr<MatGSWCiphertext_uint32> MatCipher,
		const std::shared_ptr<VecLWECiphertext_uint32> VecCipher) const;

	std::shared_ptr<VecLWECiphertext_uint32> Initialize(
		const std::shared_ptr<VecLWEparams_uint32> Vecparams,
		const uint32_t b
	)const;

	std::shared_ptr<VecLWECiphertext_uint32> InitializeBool(
		const std::shared_ptr<VecLWEparams_uint32> Vecparams,
		const uint32_t b,
		Boolean BL
	)const;

	std::shared_ptr<LWECiphertext_uint32> Bootstrapping(
		const std::shared_ptr<MatGSWparams_uint32> Matparams,
		const std::shared_ptr<VecLWEparams_uint32> Vecparams,
		const std::shared_ptr<LWECiphertext_uint32> InputLWEcipher,
		const std::shared_ptr<MatGSWSecretKey_uint32> MatSecret,
		const std::shared_ptr<LWESecretKey_uint32> InputLWESecret
	)const;

	std::shared_ptr<LWECiphertext_uint32> BootstrappingBool(
		const std::shared_ptr<MatGSWparams_uint32> Matparams,
		const std::shared_ptr<VecLWEparams_uint32> Vecparams,
		const std::shared_ptr<LWECiphertext_uint32> InputLWEcipher,
		const std::shared_ptr<MatGSWSecretKey_uint32> MatSecret,
		const std::shared_ptr<LWESecretKey_uint32> InputLWESecret,
		Boolean BL
	)const;
};

uint32_t roundingfunc_uint32(uint32_t input, uint32_t q, uint32_t t, uint64_t Q);

#endif
