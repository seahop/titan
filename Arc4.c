/**

BSD 3-Clause License

Copyright (c) 2021, Mike Gelfand
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**/

#include "Common.h"

#define ARC4_MAGIC 0x34637261 // 'arc4' (LE)

D_SEC( E ) void arc4_swap(struct arc4_context* ctx, size_t i, size_t j)
{
    uint8_t const t = ctx->s[i];
    ctx->s[i] = ctx->s[j];
    ctx->s[j] = t;
}

D_SEC( E ) uint8_t arc4_next(struct arc4_context* ctx)
{
    ctx->i += 1;
    ctx->j += ctx->s[ctx->i];

    arc4_swap(ctx, ctx->i, ctx->j);

    return ctx->s[(uint8_t)(ctx->s[ctx->i] + ctx->s[ctx->j])];
}

D_SEC( E ) void arc4_init(struct arc4_context* ctx, void const* key, size_t key_length)
{
#ifndef NDEBUG
    ctx->magic = ARC4_MAGIC;
#endif

    ctx->i = 0;
    ctx->j = 0;

    for (size_t i = 0; i < 256; ++i)
    {
        ctx->s[i] = (uint8_t)i;
    }

    for (size_t i = 0, j = 0; i < 256; ++i)
    {
        j = (uint8_t)(j + ctx->s[i] + ((uint8_t const*)key)[i % key_length]);
        arc4_swap(ctx, i, j);
    }
}

D_SEC( E ) void arc4_process(struct arc4_context* ctx, void const* src_data, void* dst_data, size_t data_length)
{
    if (data_length == 0)
    {
        return;
    }

    for (size_t i = 0; i < data_length; ++i)
    {
        ((uint8_t*)dst_data)[i] = ((uint8_t const*)src_data)[i] ^ arc4_next(ctx);
    }
}

D_SEC( E ) void arc4_discard(struct arc4_context* ctx, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        arc4_next(ctx);
    }
}
