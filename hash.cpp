
#include"hash.h"
#include<cstring>


void SM3_256_Init(SM3_256_CTX* ctx)
{
	u32 IH[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };
	int i;
	for (i = 0; i < 8; i++)
	{
		ctx->state[i] = IH[i];
	}
	memset(ctx->buffer, 0, sizeof(u32) * 16);
	ctx->bitcount = 0;
}

///////////////////////////////////////
///
///  SM3_256_Block为处理一个512 bit分块的过程，最后更新ctx中的state状态值
///  
///////////////////////////////////////
void SM3_256_Block(SM3_256_CTX* ctx)
{
	u32 A, B, C, D, E, F, G, H, temp;
	u32 SS1, SS2, TT1, TT2, Const;
	u32 W[68] = { 0 };
	int i;
	u32 t;
	u32 t1, t2 = 0x7a879d8a;
	A = ctx->state[0];	B = ctx->state[1];	C = ctx->state[2];	D = ctx->state[3];
	E = ctx->state[4];	F = ctx->state[5];	G = ctx->state[6];	H = ctx->state[7];
	////////////////Expand Message Block(消息扩展)/////////////////////
	W[0] = ctx->buffer[0];	W[1] = ctx->buffer[1];	W[2] = ctx->buffer[2];	W[3] = ctx->buffer[3];
	W[4] = ctx->buffer[4];	W[5] = ctx->buffer[5];	W[6] = ctx->buffer[6];	W[7] = ctx->buffer[7];
	W[8] = ctx->buffer[8];	W[9] = ctx->buffer[9];	W[10] = ctx->buffer[10];	W[11] = ctx->buffer[11];
	W[12] = ctx->buffer[12];	W[13] = ctx->buffer[13];	W[14] = ctx->buffer[14];	W[15] = ctx->buffer[15];
	for (i = 16; i < 68; i++)
	{
		temp = W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15);
		W[i] = P1(temp) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
	}

	/////////////Compression Function（压缩函数）///////////////////////

	for (i = 0; i < 64; i++)
	{
		if (i < 16)
		{
			Const = 0x79cc4519;
			SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Const, i), 7);
			SS2 = SS1 ^ ROTL32(A, 12);
			TT1 = FF1(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);
			TT2 = GG1(E, F, G) + H + SS1 + W[i];
		}
		else
		{
			Const = 0x7a879d8a;
			SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(Const, i), 7);
			SS2 = SS1 ^ ROTL32(A, 12);
			TT1 = FF2(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);
			TT2 = GG2(E, F, G) + H + SS1 + W[i];
		}
		D = C;
		C = ROTL32(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL32(F, 19);
		F = E;
		E = P0(TT2);
	}


	//更新状态值
	ctx->state[0] ^= A;	ctx->state[1] ^= B;	ctx->state[2] ^= C;	ctx->state[3] ^= D;
	ctx->state[4] ^= E;	ctx->state[5] ^= F;	ctx->state[6] ^= G;	ctx->state[7] ^= H;
}



///////////////////SM3 256 Hash function/////////////////////
///////////////////////////////////////
///
///  定义SM3完整hash过程
///  Inmessage代表输入的消息, MessageLen为消息长度，单位为字节
///  OutDigest代表最后的摘要, DigestLen 为摘要长度，单位为字节
///  
///////////////////////////////////////
void SM3(unsigned char* InMessage, int MessageLen, unsigned char* OutDigest, int* DigestLen)
{
	u32* p_data = (u32*)InMessage;
	int i, j;
	SM3_256_CTX ctx;
	u32* p_out = (u32*)OutDigest;
	SM3_256_Init(&ctx);

	if (MessageLen == 0)
		return;
	while (MessageLen >= 64)   //处理前面不用补位的512 bit块
	{
		for (i = 0; i < 16; i++)
		{
			REVERSE32(*p_data, ctx.buffer[i]);
			p_data++;
		}
		SM3_256_Block(&ctx);
		ctx.bitcount += 512;
		MessageLen -= 64;
	}
	///////////////////padding（填充）//////////////////////////
	for (i = 0; i < (MessageLen / 4); i++)
	{
		REVERSE32(*p_data, ctx.buffer[i]);
		p_data++;
	}
	MessageLen -= 4 * i;
	ctx.bitcount += 32 * i;
	switch (MessageLen)
	{
	case 0:
		ctx.buffer[i] = (0x80) << 24;

		break;
	case 1:
		ctx.buffer[i] = ((*(unsigned char*)p_data) << 24) | (0x80 << 16);
		ctx.bitcount += 8;
		break;
	case 2:
		ctx.buffer[i] = ((*(unsigned char*)p_data) << 24) | ((*((unsigned char*)p_data + 1)) << 16) | (0x80 << 8);
		ctx.bitcount += 16;
		break;
	case 3:
		ctx.buffer[i] = ((*(unsigned char*)p_data) << 24) | ((*((unsigned char*)p_data + 1)) << 16) | ((*((unsigned char*)p_data + 2)) << 8) | 0x80;
		ctx.bitcount += 24;
		break;

	}
	memset(&ctx.buffer[i + 1], 0, sizeof(u32) * (15 - i));
	if (i < 56)
	{
		ctx.buffer[14] = ctx.bitcount >> 32;
		ctx.buffer[15] = ctx.bitcount & 0xFFFFFFFFF;
		SM3_256_Block(&ctx);
	}
	else
	{
		SM3_256_Block(&ctx);
		memset(ctx.buffer, 0, sizeof(u32) * 16);
		*(u64*)(&ctx.buffer[15]) = ctx.bitcount;
	}
	//memcpy(OutDigest,ctx.state,sizeof(u32)*8);
	for (i = 0; i < 8; i++)
	{
		REVERSE32(ctx.state[i], *p_out);
		p_out++;
	}
	*DigestLen = 32;
}


