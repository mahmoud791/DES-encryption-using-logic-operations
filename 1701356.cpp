#ifdef __GNUC__
# define __rdtsc __builtin_ia32_rdtsc
#else
#include<intrin.h>
#endif
#include "stdio.h"
typedef unsigned long long u64;


using namespace std;

u64 hex2binary(const char*data);
u64 permute(u64 input, const char*permutation,int input_size,int output_size);
u64 permuted_choice_1(u64 key);
u64 permuted_choice_2(u64 key);
u64 * generate_all_keys(const char*key_string);
u64 left_circular_shift(u64 key,int shift_amount);
u64 initial_permutation(u64 data);
u64 inverse_initial_permutation(u64 data);
u64 expansion_permutation(u64 data);
u64 s_box(u64 data);
u64 permutation(u64 data);
u64 F(u64 data,u64 key);
u64 encryption_round(u64 data,u64 key);
u64 encrypt(const char * data_string, u64 * keys);
u64 decryption_round(u64 data,u64 key);
u64 decrypt(const char*data_string, u64 * keys);

/******************
void print(u64 in)
{   
    int count = 1;
    for (int i = 63; i >= 0; i--)
    {
          
        u64 idx = 1;
        if(in & idx<<i)printf("1");
        else printf("0");
        if(count % 8 == 0 ){printf(" ");}
        count++;   
    }
    printf("\n");
}
********************/

int main(int argc, char** argv)
{
    const char * operation = argv[1];
    const char * data = argv[2];
    const char * key = argv[3];

    u64 * allkeys = generate_all_keys(key); 
    
    if(operation[0] == 'e')
    {
        long long t1=__rdtsc();
        u64 cipher = encrypt(data,allkeys);
        long long t2=__rdtsc();
        printf("Cipher: %016llX\n", cipher);
        printf("Cycles: %lld\n", t2-t1);
    }
    else if(operation[0] == 'd')
    {
        long long t1=__rdtsc();
        u64 plain = decrypt(data,allkeys);
        long long t2=__rdtsc();
        printf("Plain: %016llX\n", plain);
        printf("Cycles: %lld\n", t2-t1);  
    }

    return 0;
}


u64 hex2binary(const char*data)
{
    u64 result=0;
    for(;;++data)
    {
        unsigned char dec = *data - '0';
        if(dec<10) result = result << 4|dec;
        else
        {
            unsigned char upper = (*data&0xDF) - 'A';
            if(upper>5)break;
            result = result << 4|upper+10;
        }
    }
    return result;
}

u64 permute(u64 in,const char*permutation,int input_size,int output_size)
{
    u64 out = 0;
    for (int i = 0; i < output_size; ++i)
    {
        out|=((in>>(input_size-permutation[output_size-1-i]))&1)<<i;
    
    }
    return out;
}

u64 permuted_choice_1(u64 key)
{
    const char permutedchoice1_table [56] = { 57, 49, 41, 33, 25, 17, 9,
                                       1, 58, 50, 42, 34, 26, 18,
                                       10, 2, 59, 51, 43, 35, 27,
                                       19, 11, 3, 60, 52, 44, 36,
                                       63, 55, 47, 39, 31, 23, 15,
                                       7, 62, 54, 46, 38, 30, 22,
                                       14, 6, 61, 53, 45, 37, 29,
                                       21, 13, 5, 28, 20, 12, 4 };
    u64 out = permute(key,permutedchoice1_table,64,56);
    return out;
}

u64 permuted_choice_2(u64 key)
{
    const char permutedchoice2_table[48] = { 14, 17, 11, 24, 1, 5,
                                  3, 28, 15, 6, 21, 10,
                                  23, 19, 12, 4, 26, 8,
                                  16, 7, 27, 20, 13, 2,
                                  41, 52, 31, 37, 47, 55,
                                  30, 40, 51, 45, 33, 48,
                                  44, 49, 39, 56, 34, 53,
                                  46, 42, 50, 36, 29, 32 };
    u64 out = permute(key,permutedchoice2_table,56,48);
    return out;

}

u64 left_circular_shift(u64 key,int shift_amount)
{
    // divide the 56 bit key int two 28 bit segments
    u64 gate = 0xFFFFFFF;
    u64 k_right = key & gate;
    u64 k_left = (key>>28) & gate;
    
    //circular shift left 
    u64 temp;
    k_right = k_right<<shift_amount;
    temp = k_right>>28;
    k_right |= temp;
    k_right &= gate;
    k_left = k_left<<shift_amount;
    temp = k_left>>28;
    k_left |= temp;
    k_left &=gate;
    return (k_left<<28)|k_right;
  
}

u64 * generate_all_keys(const char*key_string)
{
    u64 key = hex2binary(key_string);
    key = permuted_choice_1(key); 
    static u64 allkeys[16];
    u64 temp = 0;
    int shiftamount[16] = { 1, 1, 2, 2,
                        2, 2, 2, 2,
                        1, 2, 2, 2,
                        2, 2, 2, 1};

    for (int i = 0; i < 16; i++)
    {
        temp = left_circular_shift(key,shiftamount[i]);
        allkeys[i] = permuted_choice_2(temp);
        key = temp;
    }
    
    return allkeys;
    
}

u64 initial_permutation(u64 data)
{
    const char intialpermutation_table[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
                                      60, 52, 44, 36, 28, 20, 12, 4,
                                      62, 54, 46, 38, 30, 22, 14, 6,
                                      64, 56, 48, 40, 32, 24, 16, 8,
                                      57, 49, 41, 33, 25, 17, 9, 1,
                                      59, 51, 43, 35, 27, 19, 11, 3,
                                      61, 53, 45, 37, 29, 21, 13, 5,
                                      63, 55, 47, 39, 31, 23, 15, 7 };
    u64 out = permute(data,intialpermutation_table,64,64);
    return out;
}

u64 inverse_initial_permutation(u64 data)
{
    const char inverseintialpermutation_table[64] { 40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25 };
    u64 out = permute(data,inverseintialpermutation_table,64,64);
    return out;
}

u64 expansion_permutation(u64 data)
{
    const char expansionpermutation_table[48] ={ 32, 1, 2, 3, 4, 5, 4, 5,
                                          6, 7, 8, 9, 8, 9, 10, 11,
                                          12, 13, 12, 13, 14, 15, 16, 17,
                                          16, 17, 18, 19, 20, 21, 20, 21,
                                          22, 23, 24, 25, 24, 25, 26, 27,
                                          28, 29, 28, 29, 30, 31, 32, 1 };
    u64 out = permute(data,expansionpermutation_table,32,48);
    return out;
}

u64 s_box(u64 data)
{
    const u64 s_box_table [8][64] =  { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
                        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                          3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },

                        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                          13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                          13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
                        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                          13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                          10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                          3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
                        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                          14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                          11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
                        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                          10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
                        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                          13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
                        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

    const char index_permutation[6] = {1,6,2,3,4,5};
    u64 index;
    u64 out = 0;
    for (int i = 0; i < 8; i++)
    {
        index = (data>>(i*6)) & 0x3F;
        index = permute(index,index_permutation,6,6);
        out |= s_box_table[7-i][index] << i*4;

    }
    return out; 

}

u64 permutation(u64 data)
{
    const char straightpermutation_table[32] = { 16, 7, 20, 21,
                                          29, 12, 28, 17,
                                          1, 15, 23, 26,
                                          5, 18, 31, 10,
                                          2, 8, 24, 14,
                                          32, 27, 3, 9,
                                          19, 13, 30, 6,
                                          22, 11, 4, 25 };
    u64 out = permute(data,straightpermutation_table,32,32);
    return out;
}

u64 F(u64 data, u64 key)
{
    data = expansion_permutation(data);
    data ^= key;
    data = s_box(data);
    data = permutation(data);
    return data;
}

u64 encryption_round(u64 data,u64 key)
{
    u64 left_in = (data>>32) & 0xFFFFFFFF;
    u64 right_in = data & 0xFFFFFFFF;
    u64 left_out = right_in;
    u64 right_out = left_in ^ F(right_in,key);
    return (left_out<<32)|right_out;
}

u64 encrypt(const char*data_string, u64 * keys)
{
    u64 data = hex2binary(data_string);
    data = initial_permutation(data);

    for (int i = 0; i < 16; i++)
    {
        data = encryption_round(data,keys[i]);
    }

    // 32-bit swap
    u64 temp = data & 0xFFFFFFFF;
    data = data>>32;
    data |= (temp<<32);
    ////////////////////

    data = inverse_initial_permutation(data);
    return data;
}

u64 decryption_round(u64 data,u64 key)
{
   u64 left_in = (data>>32) & 0xFFFFFFFF;
   u64 right_in = data & 0xFFFFFFFF;
   u64 right_out = left_in;
   u64 left_out = right_in ^ F(left_in,key);
   return (left_out<<32)|right_out; 
}

u64 decrypt(const char*data_string, u64 * keys)
{
    u64 data = hex2binary(data_string);
    data = initial_permutation(data);

    // 32-bit swap
    u64 temp = data & 0xFFFFFFFF;
    data = data>>32;
    data |= (temp<<32);
    ////////////////////

    for (int i = 15; i >= 0; i--)
    {
        data = decryption_round(data,keys[i]);
    }

    data = inverse_initial_permutation(data);
    return data;
}

