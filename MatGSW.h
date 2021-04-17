#ifndef MATGSW_H
#define MATGSW_H

#include"MatGSWcore.h"
#include"VecLWEcore.h"

class MatGSWEncryptionScheme_uint16 {
public:
	MatGSWEncryptionScheme_uint16() {}

	std::shared_ptr<MatGSWSecretKey_uint16> KeyGen(
		const std::shared_ptr<MatGSWparams_uint16> params) const;

	std::shared_ptr<MatGSWCiphertext_uint16> Encrypt(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<const MatGSWSecretKey_uint16> sk,
		const std::shared_ptr<const MatGSWPlaintext_uint16> m) const;

	std::shared_ptr<MatGSWCiphertext_uint16> Encrypt_Fast(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<const MatGSWSecretKey_uint16> sk,
		const std::shared_ptr<const MatGSWPlaintext_uint16> m) const;

	void Decrypt(const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<const MatGSWSecretKey_uint16> sk,
		const std::shared_ptr<const MatGSWCiphertext_uint16> ct,
		MatGSWPlaintext_uint16* result) const;

	std::shared_ptr<MatGSWPlaintext_uint16> SetPerM(
		const std::shared_ptr<MatGSWparams_uint16> params, const uint32_t m) const;


	std::shared_ptr<MatGSWCiphertext_uint16> MatAdd(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<const MatGSWCiphertext_uint16> cipher1,
		const std::shared_ptr<const MatGSWCiphertext_uint16> cipher2) const;

	std::shared_ptr<MatGSWCiphertext_uint16> MatMul(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<const MatGSWCiphertext_uint16> cipher1,
		const std::shared_ptr<const MatGSWCiphertext_uint16> cipher2) const;

	std::shared_ptr<VecLWECiphertext_uint16> MatVecMul(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<VecLWEparams_uint16> params2,
		const std::shared_ptr<const MatGSWCiphertext_uint16> cipher1,
		const std::shared_ptr<const VecLWECiphertext_uint16> cipher2) const;

	uint16_t VecVecMul(
		const std::shared_ptr<MatGSWparams_uint16> params,
		const std::shared_ptr<VecLWEparams_uint16> params2,
		const vector<uint16_t> cipher1,
		const std::shared_ptr<const VecLWECiphertext_uint16> cipher2) const;
};

vector<uint16_t> Ginverse_uint16(uint16_t number, long l);//G inverse of one number leas bit in front
vector<uint16_t> vecGinverse_uint16(vector<uint16_t> vec_number, long row, long l);// G inverse of a vector 

vector<vector<uint16_t>> matGinverse_uint16(vector<vector<uint16_t>> mat_number, long row, long colum, long l);// G inverse of a mat, return matrix is colum form




//------------------------------uint32----------------



class MatGSWEncryptionScheme_uint32 {
public:
	MatGSWEncryptionScheme_uint32() {}

	std::shared_ptr<MatGSWSecretKey_uint32> KeyGen(
		const std::shared_ptr<MatGSWparams_uint32> params) const;

	std::shared_ptr<MatGSWCiphertext_uint32> Encrypt(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
		const std::shared_ptr<const MatGSWPlaintext_uint32> m) const;

	std::shared_ptr<MatGSWCiphertext_uint32> Encrypt_Fast(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
		const std::shared_ptr<const MatGSWPlaintext_uint32> m) const;
	
    void Encrypt_Fast_TEST(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
		const std::shared_ptr<const MatGSWPlaintext_uint32> m, double &onetime) const;
	
    void Decrypt(const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWSecretKey_uint32> sk,
		const std::shared_ptr<const MatGSWCiphertext_uint32> ct,
		MatGSWPlaintext_uint32* result) const;

	std::shared_ptr<MatGSWPlaintext_uint32> SetPerM(
		const std::shared_ptr<MatGSWparams_uint32> params, const uint32_t m) const;

	std::shared_ptr<MatGSWCiphertext_uint32> MatAdd(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
		const std::shared_ptr<const MatGSWCiphertext_uint32> cipher2) const;

	std::shared_ptr<MatGSWCiphertext_uint32> MatMul(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
		const std::shared_ptr<const MatGSWCiphertext_uint32> cipher2) const;

	std::shared_ptr<VecLWECiphertext_uint32> MatVecMul(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<VecLWEparams_uint32> params2,
		const std::shared_ptr<const MatGSWCiphertext_uint32> cipher1,
		const std::shared_ptr<const VecLWECiphertext_uint32> cipher2) const;

	uint32_t VecVecMul(
		const std::shared_ptr<MatGSWparams_uint32> params,
		const std::shared_ptr<VecLWEparams_uint32> params2,
		const vector<uint32_t> cipher1,
		const std::shared_ptr<const VecLWECiphertext_uint32> cipher2) const;
};

vector<uint32_t> Ginverse_uint32(uint32_t number, long l);//G inverse of one number leas bit in front
vector<uint32_t> vecGinverse_uint32(vector<uint32_t> vec_number, long row, long l);// G inverse of a vector 

vector<vector<uint32_t>> matGinverse_uint32(vector<vector<uint32_t>> mat_number, long row, long colum, long l);// G inverse of a mat, return matrix is colum form
#endif
