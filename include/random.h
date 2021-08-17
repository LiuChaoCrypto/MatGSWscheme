#pragma once
#ifndef RANDOM_H
#define RANDOM_H


#include<cstring>
#include "hash.h"

//#include "aes/aes.h"
//#include"header.h"

extern unsigned char AES_KEY_new[32];
extern unsigned char AES_SCH_new[240];


struct RNG_New {

	int outlen = 0;
	unsigned char* InMessage;// [32] = { 0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19, 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31 };
	int MessageLen;
	unsigned char* output1;// [32] = { 0 };
	RNG_New() {

		InMessage = new unsigned char[32];
		output1 = new unsigned char[32];
	}
	void init(unsigned char* s, unsigned long long s_byts) {
		memset(InMessage, 0, sizeof(InMessage));
		//MessageLen = (in.length() > 32) ? 32 : in.length();
		memcpy(InMessage, s, 32);
		SM3(InMessage, s_byts, output1, &outlen);
		memcpy(InMessage, output1, 32);
	}
	void reset() {
		MessageLen = 32;
		SM3(InMessage, MessageLen, output1, &outlen);
		memcpy(InMessage, output1, 32);
	}

	void call_bytes(unsigned char* re, int number) {
		if (number > outlen)
			this->reset();
		memcpy(re, output1 + outlen - number, number);
		outlen -= number;
	}
};
extern short Sample_Table1_new[1024];
extern short Sample_Table2_new[27]; 

short sampler_New(int a, int b, unsigned char* output, RNG_New* RNG); 
//For the Gauss sampling technique used here, refer to https://eprint.iacr.org/2019/1231.pdf 
#endif // !RANDOM_H
