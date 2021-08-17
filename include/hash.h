// SM3.cpp : 定义控制台应用程序的入口点。
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
///  以下7个函数为轮函数中用到的函数
///
///////////////////////////////////////
#define FF1(X,Y,Z) (X^Y^Z)
#define FF2(X,Y,Z) ((X&Y)|(X&Z)|(Y&Z))
#define GG1(X,Y,Z) (X^Y^Z)
#define GG2(X,Y,Z) ((X&Y)|((~X)&Z))
#define ROTL32(X,num) ((X<<num)|(X>>(32-num)))
#define P0(X) ((X)^ROTL32((X),9)^ROTL32((X),17))
#define P1(X) ((X)^ROTL32((X),15)^ROTL32((X),23))

//将32bit的数所包含的四个字节顺序翻转
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

//将中间状态值初始化为IV
void SM3_256_Init(SM3_256_CTX* ctx);


///////////////////////////////////////
///
///  SM3_256_Block为处理一个512 bit分块的过程，最后更新ctx中的state状态值
///  
///////////////////////////////////////
void SM3_256_Block(SM3_256_CTX* ctx);



///////////////////SM3 256 Hash function/////////////////////
///////////////////////////////////////
///
///  定义SM3完整hash过程
///  Inmessage代表输入的消息, MessageLen为消息长度，单位为字节
///  OutDigest代表最后的摘要, DigestLen 为摘要长度，单位为字节
///  
///////////////////////////////////////
void SM3(unsigned char* InMessage, int MessageLen, unsigned char* OutDigest, int* DigestLen);


 
#endif
