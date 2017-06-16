double_quarter_round_32(v0, v1, v2, v3)
{
        v0 += v1;
        v3 ^= v0;
        v3 <<<= 16;

        v2 += v3;
        v1 ^= v2;
        v1 <<<= 12;

        v0 += v1;
        v3 ^= v0;
        v3 <<<= 8;

        v2 += v3;
        v1 ^= v2;
        v1 <<<= 7;
}

double_quarter_round_64(v0, v1, v2, v3)
{
        
}


/*
 * 128-bit vectors
 * Algorithm 5: DOUBLEQUARTERROUND (optimized for 128-bit vectors)
 * Input: v0, v1, v2, v3 (state matrix as four 4x32-bit vectors,
 * each vector includes one row)
 * Output: v0, v1, v2, v3 (updated state matrix)
 * Flow
 * v0 += v1; v3 ^= v0; v3 <<<= (16, 16, 16, 16);
 * v2 += v3; v1 ^= v2; v1 <<<= (12, 12, 12, 12);
 * v0 += v1; v3 ^= v0; v3 <<<= ( 8, 8, 8, 8);
 * v2 += v3; v1 ^= v2; v1 <<<= ( 7, 7, 7, 7);
 * v1 >>>= 32; v2 >>>= 64; v3 >>>= 96;
 * v0 += v1; v3 ^= v0; v3 <<<= (16, 16, 16, 16);
 * v2 += v3; v1 ^= v2; v1 <<<= (12, 12, 12, 12);
 * v0 += v1; v3 ^= v0; v3 <<<= ( 8, 8, 8, 8);
 * v2 += v3; v1 ^= v2; v1 <<<= ( 7, 7, 7, 7);
 * v1 <<<= 32; v2 <<<= 64; v3 <<<= 96;
 * Return
 */

double_quarter_round_128(v0, v1, v2, v3)
{
        v0 += v1;
        v3 ^= v0;
        v3 <<<= (16,16,16,16);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= (12,12,12,12);

        v0 += v1;
        v3 ^= v0;
        v3 <<<= ( 8, 8, 8, 8);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= ( 7, 7, 7, 7);

        v1 >>>= 32;
        v2 >>>= 64;
        v3 >>>= 96;

        v0 += v1;
        v3 ^= v0;
        v3 <<<= (16,16,16,16);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= (12,12,12,12);

        v0 += v1;
        v3 ^= v0;
        v3 <<<= ( 8, 8, 8, 8);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= ( 7, 7, 7, 7);

        v1 <<<= 32;
        v2 <<<= 64;
        v3 <<<= 96;
}


/*
 * 256-bit vectors
 *
 * Algorithm 6: DOUBLEQUARTERROUND (optimized for 256-bit vectors)
 * Input: v0, v1, v2, v3 (2 state matrices as 4 8x32-bit vectors,
 * each vector includes one row
 * of each matrix)
 * Output: v0, v1, v2, v3 (updated state matrices)
 * Flow
 * v0 += v1; v3 ^= v0; v3 <<<= (16,16,16,16,16,16,16,16);
 * v2 += v3; v1 ^= v2; v1 <<<= (12,12,12,12,12,12,12,12);
 * v0 += v1; v3 ^= v0; v3 <<<= ( 8, 8, 8, 8, 8, 8, 8, 8);
 * v2 += v3; v1 ^= v2; v1 <<<= ( 7, 7, 7, 7, 7, 7, 7, 7);
 * v1 >>>= 32; v2 >>>= 64; v3 >>>= 96;
 * v0 += v1; v3 ^= v0; v3 <<<= (16,16,16,16,16,16,16,16);
 * v2 += v3; v1 ^= v2; v1 <<<= (12,12,12,12,12,12,12,12);
 * v0 += v1; v3 ^= v0; v3 <<<= ( 8, 8, 8, 8, 8, 8, 8, 8);
 * v2 += v3; v1 ^= v2; v1 <<<= ( 7, 7, 7, 7, 7, 7, 7, 7);
 * v1 <<<= 32; v2 <<<= 64; v3 <<<= 96;
 * Return
 */

double_quarter_round_256(v0, v1, v2, v3)
{
        v0 += v1;
        v3 ^= v0;
        v3 <<<= (16,16,16,16,16,16,16,16);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= (12,12,12,12,12,12,12,12);

        v0 += v1;
        v3 ^= v0;
        v3 <<<= ( 8, 8, 8, 8, 8, 8, 8, 8);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= ( 7, 7, 7, 7, 7, 7, 7, 7);

        v1 >>>= 32;
        v2 >>>= 64;
        v3 >>>= 96;

        v0 += v1;
        v3 ^= v0;
        v3 <<<= (16,16,16,16,16,16,16,16);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= (12,12,12,12,12,12,12,12);

        v0 += v1;
        v3 ^= v0;
        v3 <<<= ( 8, 8, 8, 8, 8, 8, 8, 8);

        v2 += v3;
        v1 ^= v2;
        v1 <<<= ( 7, 7, 7, 7, 7, 7, 7, 7);

        v1 <<<= 32;
        v2 <<<= 64;
        v3 <<<= 96;
}

double_quarter_round_512vec(v0, v1, v2, v3)
{

}



/*****************************************************************************/

chacha20_64_sse(state0,
                state1,
                state2,
                state3)
{

}

poly1305_64_sse(xxx,
                xxx,
                xxx,
                src0,
                src1,
                src2,
                src3)
{

}

xor_64_sse(dst0,
           dst1,
           dst2,
           dst3,
           src0,
           src1,
           src2,
           src3)
{


}

