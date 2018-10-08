/**
 * md2-base.c - Message Digest 2 algorithm as defined in RFC 1319
 *
 * Copyright (c) 2018, Tobias Heilig
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * https://ietf.org/rfc/rfc1319.txt
 **/



#include <stdlib.h>
#include <string.h>


#define MD2_BLOCK_SIZE 16

#define MD2_DIGEST_LEN 16


typedef unsigned char BYTE;


typedef struct {
    BYTE state[16];
    BYTE data[16];
    BYTE checksum[16];
    int len;
} MD2_CTX;


static const BYTE s[256] = {
  0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13, 
  0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA, 
  0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12, 
  0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A, 
  0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
  0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03, 
  0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6, 
  0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1, 
  0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02, 
  0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F, 
  0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26, 
  0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52, 
  0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A, 
  0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39, 
  0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A, 
  0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14
};


static void
md2_transform (MD2_CTX *ctx, BYTE *data)
{

    int j, k, t;
    BYTE x[48];


    memcpy(&x, ctx->state, 16);

    memcpy(&x[16], data, 16);
    
    x[32] = x[16] ^ x[0]; 
    x[33] = x[17] ^ x[1];
    x[34] = x[18] ^ x[2];
    x[35] = x[19] ^ x[3];
    x[36] = x[20] ^ x[4];
    x[37] = x[21] ^ x[5];
    x[38] = x[22] ^ x[6];
    x[39] = x[23] ^ x[7];
    x[40] = x[24] ^ x[8];
    x[41] = x[25] ^ x[9];
    x[42] = x[26] ^ x[10];
    x[43] = x[27] ^ x[11];
    x[44] = x[28] ^ x[12];
    x[45] = x[29] ^ x[13];
    x[46] = x[30] ^ x[14];
    x[47] = x[31] ^ x[15];

    
    t = 0;

    for (j = 0; j < 18; ++j) {

        for (k = 0; k < 48; k += 8) {
            t = x[k+0] ^= s[t];
            t = x[k+1] ^= s[t];
            t = x[k+2] ^= s[t];
            t = x[k+3] ^= s[t];
            t = x[k+4] ^= s[t];
            t = x[k+5] ^= s[t];
            t = x[k+6] ^= s[t];
            t = x[k+7] ^= s[t];
        }

        t = (t + j) & 0xff;
    }


    memcpy(ctx->state, &x, 16);


    t = ctx->checksum[15];

    for (j = 0; j < 16; ++j) {
        t = ctx->checksum[j] ^= s[data[j] ^ t];
    }
    
}


void
MD2_Init (MD2_CTX *ctx)
{

    memset(ctx->state, 0, 16);
    memset(ctx->checksum, 0, 16);
    ctx->len = 0;    

}


void
MD2_Update (MD2_CTX *ctx, const BYTE *data, size_t len)
{

    for (size_t i = 0; i < len; ++i) {

		ctx->data[ctx->len] = data[i];
		ctx->len++;

		if (ctx->len == MD2_BLOCK_SIZE) {
			md2_transform(ctx, ctx->data);
			ctx->len = 0;
		}
    }
}


void
MD2_Final (MD2_CTX *ctx, BYTE *digest)
{

    int i = MD2_BLOCK_SIZE - ctx->len;

    memset(&ctx->data[ctx->len], i, i);

    md2_transform(ctx, ctx->data);
    md2_transform(ctx, ctx->checksum);

    memcpy(digest, ctx->state, MD2_BLOCK_SIZE);

}

