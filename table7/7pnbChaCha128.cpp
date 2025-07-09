#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>

#define ul unsigned int
#define ull unsigned long long

#define rotateleft(x, n) (((x) << (n)) ^ ((x) >> (32 - n)))
#define rotateright(x, n) (((x) >> (n)) ^ ((x) << (32 - n)))

#define update(a, b, n) ((rotateleft((a) ^ (b), (n))))
#define myrand32 ((ul)(4294967296.0 * drand48()))

ull MOD = 4294967296;

void initializeR(ul *x)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        x[i] = myrand32;
    }
    x[0] = 0x61707865;
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;


    x[4] =  x[8];
    x[5] =  x[9];
    x[6] =  x[10];
    x[7] =  x[11];

}

void print(ul *x)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        printf("%8x ", x[i]);
        if (i > 0 && i % 4 == 3)
            printf("\n");
    }
    printf("\n");
}

uint32_t createMask(uint8_t n)
{
    // Shift 1 left by (n + 1) and subtract 1 to set the lower (n + 1) bits
    return (1U << (n + 1)) - 1;
}

uint32_t extractBits(uint32_t input, uint8_t n)
{
    // Create a mask for the lower 23 bits (0-22)
    uint32_t mask = createMask(n); // Binary: 00000000011111111111111111111111
    return input & mask;           // Use bitwise AND to extract the lower 23 bits
}

void copystate(ul *x1, ul *x)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        x1[i] = x[i];
    }
}

void qr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul z0, z1, z2, z3;

    z0 = *x0 + *x1;
    z3 = update(*x3, z0, 16);
    z2 = *x2 + z3;
    z1 = update(*x1, z2, 12);
    z0 = z0 + z1;
    z3 = update(z3, z0, 8);
    z2 = z2 + z3;
    z1 = update(z1, z2, 7);

    *x0 = z0, *x1 = z1, *x2 = z2, *x3 = z3;
}

void fhalfqr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul p, q, r, s;

    p = *x0;
    q = *x1;
    r = *x2;
    s = *x3;

    p += q;
    s ^= p;
    s = rotateleft(s, 16);
    r += s;
    q ^= r;
    q = rotateleft(q, 12);

    // p ^= q; s ^= p; s = rotateleft(s,25);
    // r ^= s; q ^= r; q = rotateleft(q,5);

    *x0 = p;
    *x1 = q;
    *x2 = r;
    *x3 = s;
}

void shalfqr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul p, q, r, s;

    p = *x0;
    q = *x1;
    r = *x2;
    s = *x3;

    // p ^= q; s ^= p; s = rotateleft(s,19);
    // r ^= s; q ^= r; q = rotateleft(q,17);
    p += q;
    s ^= p;
    s = rotateleft(s, 8);
    r += s;
    q ^= r;
    q = rotateleft(q, 7);

    *x0 = p;
    *x1 = q;
    *x2 = r;
    *x3 = s;
}

void roundodd(ul *x)
{
    qr(&(x[0]), &(x[4]), &(x[8]), &(x[12]));
    qr(&(x[1]), &(x[5]), &(x[9]), &(x[13]));
    qr(&(x[2]), &(x[6]), &(x[10]), &(x[14]));
    qr(&(x[3]), &(x[7]), &(x[11]), &(x[15]));
}

void roundeven(ul *x)
{
    qr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
    qr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    qr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    qr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
}

void fhalfroundeven(ul *x)
{

    fhalfqr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
    fhalfqr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    fhalfqr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    fhalfqr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
    // transpose(x);
}

void shalfroundeven(ul *x)
{

    shalfqr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
    shalfqr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    shalfqr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    shalfqr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
    // transpose(x);
}

void inqr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul p, q, r, s;

    p = *x0, q = *x1, r = *x2, s = *x3;

    q = rotateright(q, 7);
    q ^= r;
    r -= s;
    s = rotateright(s, 8);
    s ^= p;
    p -= q;
    q = rotateright(q, 12);
    q ^= r;
    r -= s;
    s = rotateright(s, 16);
    s ^= p;
    p -= q;

    *x0 = p, *x1 = q, *x2 = r, *x3 = s;
}

void sinqr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul p, q, r, s;

    p = *x0, q = *x1, r = *x2, s = *x3;

    q = rotateright(q, 7);
    q ^= r;
    r -= s;
    s = rotateright(s, 8);
    s ^= p;
    p -= q;
    // q = rotateright(q, 17);
    // q ^= r;
    // r -= s;
    // s = rotateright(s, 19);
    // s ^= p;
    // p -= q;

    *x0 = p, *x1 = q, *x2 = r, *x3 = s;
}

void finqr(ul *x0, ul *x1, ul *x2, ul *x3)
{
    ul p, q, r, s;

    p = *x0, q = *x1, r = *x2, s = *x3;

    // q = rotateright(q, 11);
    // q ^= r;
    // r -= s;
    // s = rotateright(s, 25);
    // s ^= p;
    // p -= q;
    q = rotateright(q, 12);
    q ^= r;
    r -= s;
    s = rotateright(s, 16);
    s ^= p;
    p -= q;

    *x0 = p, *x1 = q, *x2 = r, *x3 = s;
}

void inroundo(ul *x)
{
    inqr(&(x[3]), &(x[7]), &(x[11]), &(x[15]));
    inqr(&(x[2]), &(x[6]), &(x[10]), &(x[14]));
    inqr(&(x[1]), &(x[5]), &(x[9]), &(x[13]));
    inqr(&(x[0]), &(x[4]), &(x[8]), &(x[12]));
}

void inrounde(ul *x)
{
    inqr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
    inqr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    inqr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    inqr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
}

void sinrounde(ul *x)
{
    sinqr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
    sinqr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    sinqr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    sinqr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
}

void finrounde(ul *x)
{
    finqr(&(x[3]), &(x[4]), &(x[9]), &(x[14]));
    finqr(&(x[2]), &(x[7]), &(x[8]), &(x[13]));
    finqr(&(x[1]), &(x[6]), &(x[11]), &(x[12]));
    finqr(&(x[0]), &(x[5]), &(x[10]), &(x[15]));
}
void sinroundo(ul *x)
{

    sinqr(&(x[3]), &(x[7]), &(x[11]), &(x[15]));
    sinqr(&(x[2]), &(x[6]), &(x[10]), &(x[14]));
    sinqr(&(x[1]), &(x[5]), &(x[9]), &(x[13]));
    sinqr(&(x[0]), &(x[4]), &(x[8]), &(x[12]));
}

void finroundo(ul *x)
{

    finqr(&(x[3]), &(x[7]), &(x[11]), &(x[15]));
    finqr(&(x[2]), &(x[6]), &(x[10]), &(x[14]));
    finqr(&(x[1]), &(x[5]), &(x[9]), &(x[13]));
    finqr(&(x[0]), &(x[4]), &(x[8]), &(x[12]));
}

int main()
{
    ul x[16], x1[16], x0[16], x01[16], z1[16], z2[16], diff, diff1, pattern, pt;
    int i, j, j1, j2, j3, j4,

        A[] = {71};

    ul u1, u2, u3;

    int ll1 = 0, ll2 = 0, ll3 = 1, L = 1, count;

    ull loop = 0;
    double cnt = 0;

    srand48(time(NULL));

    while (loop < 1024 * 256)
    {
        count = 0;
        while (1)
        {
            initializeR(x);
            copystate(x1, x);

            pt = (0x00000001 << 6);

            x1[13] = x[13] ^ pt;

            copystate(x0, x);
            copystate(x01, x1);

            roundodd(x);
            roundodd(x1);
            roundeven(x);
            roundeven(x1);
            roundodd(x);
            roundodd(x1);
            roundeven(x);
            roundeven(x1);

            diff = ((x[2] ^ x1[2]) << 7) ^ ((x[8] ^ x1[8]) << 7) ^ ((x[7] ^ x1[7]));

            roundodd(x);
            roundodd(x1);

            roundeven(x);
            roundeven(x1);
            roundodd(x);
            roundodd(x1);

            
            for (i = 0; i < 16; i++)
            {
                z1[i] = (x[i] + x0[i]);
                z2[i] = (x1[i] + x01[i]);
            }

            j = 0;

            j1 = (A[j] / 32) + 4;
            j2 = A[j] % 32;

            uint32_t Z1 = extractBits(z1[j1], 18);
            uint32_t Z2 = extractBits(z2[j1], 18);
            uint32_t X = extractBits(x[j1],   18);
            uint32_t X1 = extractBits(x1[j1], 18);

            uint32_t T1 = extractBits(z1[j1+4], 18);
            uint32_t T2 = extractBits(z2[j1+4], 18);
            uint32_t Y = extractBits  (x[j1+4], 18);
            uint32_t Y1 = extractBits(x1[j1+4], 18);

            if (
                (Z1>X) && (Z2>X1)&
                (((z2[j1] >> (j2 + 1)) % 2) != 0) && (((z1[j1] >> (j2 + 1)) % 2) != 0) &&
                (((z2[j1] >> (j2 + 2)) % 2) != 0) && (((z1[j1] >> (j2 + 2)) % 2) != 0) &&
                (((z2[j1] >> j2) % 2) != 0) && (((z1[j1] >> j2) % 2) != 0) 
            
            )
                count = count + 1;

            if (count == 1)
                break;
        }

/******************PNB flipping *************************** */

        if (drand48() < 0.5)
        {
            x0[j1] = x0[j1] ^ (0x00000001 << j2);
            x01[j1] = x01[j1] ^ (0x00000001 << j2);

             x0[j1+4] =  x0[j1+4] ^ (0x00000001 << j2);
            x01[j1+4] = x01[j1+4] ^ (0x00000001 << j2);
        }

        if (drand48() < 0.5)
        {
            x0[j1] = x0[j1] ^   (0x00000001 << j2+1);
            x01[j1] = x01[j1] ^ (0x00000001 << j2+1);

             x0[j1+4] =  x0[j1+4] ^ (0x00000001 << j2+1);
            x01[j1+4] = x01[j1+4] ^ (0x00000001 << j2+1);
        }

        if (drand48() < 0.5)
        {
            x0[j1] = x0[j1] ^   (0x00000001 << j2+2);
            x01[j1] = x01[j1] ^ (0x00000001 << j2+2);

             x0[j1+4] =  x0[j1+4] ^ (0x00000001 << j2+2);
            x01[j1+4] = x01[j1+4] ^ (0x00000001 << j2+2);
        }
      

// /********************************************* */

        for (i = 0; i < 16; i++)
        {
            x[i] = z1[i] + (MOD - (x0[i]));
            x1[i] = z2[i] + (MOD - (x01[i]));
        }

        
        inroundo(x);
        inroundo(x1);
        inrounde(x);
        inrounde(x1);
        inroundo(x);
        inroundo(x1);

        pattern = 0x00000001 << 7;

        diff1 = ((x[2] ^ x1[2]) << 7) ^ ((x[8] ^ x1[8]) << 7) ^ ((x[7] ^ x1[7]));

    

        if (((diff ^ diff1) & pattern) == 0)
        {
            cnt = cnt + 1.0;
        }

        loop++;

        if (loop > 0 && loop % (1024 * 4) == 0)
            printf(" %llu      %0.10f   \n", loop / (1024 * 4), 2 * ((cnt / loop) - 0.5));
    }
}
