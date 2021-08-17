// SM3.cpp : �������̨Ӧ�ó������ڵ㡣
//

//#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string>

#ifndef  SM3_H
#define SM3_H
 // ! SM3_H


using namespace std;


typedef unsigned int u32;
typedef unsigned char u8;
typedef uint64_t u64;
///////////////////////////////////////
///
///  ����7������Ϊ�ֺ������õ��ĺ���
///
///////////////////////////////////////
#define FF1(X,Y,Z) (X^Y^Z)
#define FF2(X,Y,Z) ((X&Y)|(X&Z)|(Y&Z))
#define GG1(X,Y,Z) (X^Y^Z)
#define GG2(X,Y,Z) ((X&Y)|((~X)&Z))
#define ROTL32(X,num) ((X<<num)|(X>>(32-num)))
#define P0(X) ((X)^ROTL32((X),9)^ROTL32((X),17))
#define P1(X) ((X)^ROTL32((X),15)^ROTL32((X),23))

//��32bit�������������ĸ��ֽ�˳��ת
#define REVERSE32(w,x) {\
	u32 tmp=(w);\
	tmp = (tmp>>16) | (tmp<<16);\
	(x) = (((tmp&0xff00ff00)>>8) | ((tmp&0x00ff00ff)<<8));\
}
typedef struct
{
	u32 state[8];
	u64 bitcount;
	u32 buffer[16];
}SM3_256_CTX;

/////////////Set Init Value////////////////
const u32 T[64] = { 0x79cc4519,0xf3988a32,0xe7311465,0xce6228cb,0x9cc45197,0x3988a32f,0x7311465e,0xe6228cbc,0xcc451979,0x988a32f3,0x311465e7,0x6228cbce,
0xc451979c,0x88a32f39,0x11465e73,0x228cbce6,0x9d8a7a87,0x3b14f50f,0x7629ea1e,0xec53d43c,0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,0x8a7a879d,
0x14f50f3b,0x29ea1e76,0x53d43cec,0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5,0x7a879d8a,0xf50f3b14,0xea1e7629,0xd43cec53,0xa879d8a7,0x50f3b14f,
0xa1e7629e,0x43cec53d,0x879d8a7a,0x0f3b14f5,0x1e7629ea,0x3cec53d4,0x79d8a7a8,0xf3b14f50,0xe7629ea1,0xcec53d43,0x9d8a7a87,0x3b14f50f,0x7629ea1e,
0xec53d43c,0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,0x8a7a879d,0x14f50f3b,0x29ea1e76,0x53d43cec,0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5 };

//���м�״ֵ̬��ʼ��ΪIV
void SM3_256_Init(SM3_256_CTX* ctx);


///////////////////////////////////////
///
///  SM3_256_BlockΪ����һ��512 bit�ֿ�Ĺ��̣�������ctx�е�state״ֵ̬
///  
///////////////////////////////////////
void SM3_256_Block(SM3_256_CTX* ctx);



///////////////////SM3 256 Hash function/////////////////////
///////////////////////////////////////
///
///  ����SM3����hash����
///  Inmessage�����������Ϣ, MessageLenΪ��Ϣ���ȣ���λΪ�ֽ�
///  OutDigest��������ժҪ, DigestLen ΪժҪ���ȣ���λΪ�ֽ�
///  
///////////////////////////////////////
void SM3(unsigned char* InMessage, int MessageLen, unsigned char* OutDigest, int* DigestLen);


 
#endif
