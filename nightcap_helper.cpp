#include <memory.h>
#include <math.h>
#include <sys/stat.h>
#include <stdio.h>

#include "stratum.h"
#include "nightcap_helper.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_bmw.h"

extern "C" {
   #include "algos/crypto/Lyra2.h"
}

#define WORD_BYTES 4
#define DATASET_BYTES_INIT 536870912
#define DATASET_BYTES_GROWTH 12582912
#define CACHE_BYTES_INIT 8388608
#define CACHE_BYTES_GROWTH 196608
#define EPOCH_LENGTH 400
#define CACHE_MULTIPLIER 64
#define MIX_BYTES 64
#define HASH_BYTES 32
#define DATASET_PARENTS 256
#define CACHE_ROUNDS 3
#define ACCESSES 64
#define FNV_PRIME 0x01000193

int is_prime(unsigned long number)
{
    if (number <= 1) return false;
    if((number % 2 == 0) && number > 2) return false;
    for(unsigned long i = 3; i < sqrt(number); i += 2) {
        if(number % i == 0)
            return false;
    }
    return true;
}

unsigned int fnv(unsigned int v1, unsigned int v2)
{
    return ((v1 * FNV_PRIME)  ^ v2) % (0xffffffff);
}

unsigned long get_cache_size(unsigned long block_number)
{
    unsigned long sz = CACHE_BYTES_INIT + (CACHE_BYTES_GROWTH * round(sqrt(6*(block_number / EPOCH_LENGTH))));
    sz -= HASH_BYTES;
    while (!is_prime(sz / HASH_BYTES)) {
        sz -= 2 * HASH_BYTES;
    }
    return sz;
}

unsigned long get_full_size(unsigned long block_number)
{
    unsigned long sz = DATASET_BYTES_INIT + (DATASET_BYTES_GROWTH * round(sqrt(6*(block_number / EPOCH_LENGTH))));
    sz -= MIX_BYTES;
    while (!is_prime(sz / MIX_BYTES)) {
        sz -= 2 * MIX_BYTES;
    }
    return sz;
}

uint32_t* mkcache(unsigned long size, char *seed)
{
    uint64_t items = size / HASH_BYTES;
    printf("\n");
    fflush(stdout);
    uint32_t *cache = (uint32_t*)malloc(size);
    int64_t hashwords = HASH_BYTES / WORD_BYTES;
    sph_blake256_context ctx;
    sph_blake256_init(&ctx);
    sph_blake256(&ctx, seed, HASH_BYTES);
    sph_blake256_close(&ctx, cache);
    for(uint64_t i = 1; i < items; i++) {
        sph_blake256_init(&ctx);
        sph_blake256(&ctx, cache + ((i-1) * (hashwords)), HASH_BYTES);
        sph_blake256_close(&ctx, cache + i*hashwords);
    }
    for(uint64_t round = 0; round < CACHE_ROUNDS; round++) {
        for(uint64_t i = 0; i < items; i++) {
            uint64_t target = cache[(i * (HASH_BYTES / sizeof(uint32_t)))] % items;
            uint64_t mapper = (i - 1 + items) % items;
            uint32_t item[HASH_BYTES / sizeof(uint32_t)];
            for(uint64_t dword = 0; dword < (HASH_BYTES / sizeof(uint32_t)); dword++) {
                item[dword] = cache[(mapper * (HASH_BYTES / sizeof(uint32_t))) + dword]
                            ^ cache[(target * (HASH_BYTES / sizeof(uint32_t))) + dword];
            }
            sph_blake256_init(&ctx);
            sph_blake256(&ctx, item, HASH_BYTES);
            sph_blake256_close(&ctx, item);
            memcpy(cache + (i * (HASH_BYTES / sizeof(uint32_t))), item, HASH_BYTES);
        }
    }
    FILE* file = fopen("cache", "wb");
    fwrite(cache, 1, size, file);
    fclose(file);
    return cache;
}

uint32_t *calc_dataset_item(uint32_t *cache, unsigned long i, unsigned long cache_size)
{
    sph_blake256_context ctx;
    uint64_t items = cache_size / HASH_BYTES;
    uint64_t hashwords = HASH_BYTES / WORD_BYTES;
    uint32_t *mix = (uint32_t*)malloc(HASH_BYTES);
    memcpy(mix, cache + (i % items)*hashwords, HASH_BYTES);
    mix[0] ^= i;
    sph_blake256_init(&ctx);
    sph_blake256(&ctx, mix, HASH_BYTES);
    sph_blake256_close(&ctx, mix);
    for(uint64_t parent = 0; parent < DATASET_PARENTS; parent++) {
        uint64_t index = fnv(i ^ parent, mix[parent % (HASH_BYTES / sizeof(uint32_t))]) % items;
        for(uint64_t dword = 0; dword < (HASH_BYTES / sizeof(uint32_t)); dword++) {
            mix[dword] = fnv(mix[dword], cache[index * (HASH_BYTES / sizeof(uint32_t))]);
        }
    }
    sph_blake256_init(&ctx);
    sph_blake256(&ctx, mix, HASH_BYTES);
    sph_blake256_close(&ctx, mix);
    return mix;
}

uint32_t* calc_full_dataset(uint32_t *cache, unsigned long dataset_size, unsigned long cache_size, int thr_id, uint64_t epoch)
{
    int spinner = 0; int spinnerasc = 0;
    uint32_t *fullset = (uint32_t*)malloc(dataset_size);
    char n[33];
    memset(n, 0, 33);
    sprintf(n, "%d", epoch);
    const char *dagn = strcat(n, "dag");
    struct stat res;
    if((!stat(dagn, &res) && S_ISREG(res.st_mode))) {
        if(res.st_size == dataset_size) {
            FILE* file = fopen(dagn, "rb");
            fread(fullset, 1, dataset_size, file);
            fclose(file);
            return fullset;
        }
    }
    #pragma omp parallel for
    for(int i = 0; i < (dataset_size / HASH_BYTES); i++){
        char *item = (char*) calc_dataset_item(cache, i, cache_size);
        memcpy(fullset + i*8, item, 32);
	if (i % 1000 == 0) {
            spinner++;
            if (spinner==0)     { spinnerasc = 92;  }
            else if(spinner==1) { spinnerasc = 124; }
            else if(spinner==2) { spinnerasc = 47;  }
            else if(spinner==3) { spinnerasc = 45;  }
            else if(spinner==4) { spinner = 0; spinnerasc = 92; }
            printf("\rgenerating dag - %d of %d %c ", i, (dataset_size / HASH_BYTES), spinnerasc); 
        }
	//if(!(i % ((dataset_size / HASH_BYTES)/4)))
        //   printf("%u/%lu items finished.", i, (dataset_size/HASH_BYTES));
        free(item);
    }
    if(!thr_id) {
        FILE* file = fopen(dagn, "wb");
        fwrite(fullset, 1, dataset_size, file);
        fclose(file);
    }
    return fullset;
}

static void lyra2re2_hash(const void* input, void* state, int length)
{
	uint32_t hashA[8], hashB[8];

	sph_blake256_context     ctx_blake;
	sph_keccak256_context    ctx_keccak;
	sph_cubehash256_context  ctx_cubehash;
	sph_skein256_context     ctx_skein;
	sph_bmw256_context       ctx_bmw;

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, length);
	sph_blake256_close(&ctx_blake, hashA);

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256(&ctx_keccak, hashA, 32);
	sph_keccak256_close(&ctx_keccak, hashB);

	sph_cubehash256_init(&ctx_cubehash);
	sph_cubehash256(&ctx_cubehash, hashB, 32);
	sph_cubehash256_close(&ctx_cubehash, hashA);

	LYRA2(hashB, 32, hashA, 32, hashA, 32, 1, 4, 4);

	sph_skein256_init(&ctx_skein);
	sph_skein256(&ctx_skein, hashB, 32);
	sph_skein256_close(&ctx_skein, hashA);

	sph_cubehash256_init(&ctx_cubehash);
	sph_cubehash256(&ctx_cubehash, hashA, 32);
	sph_cubehash256_close(&ctx_cubehash, hashB);

	sph_bmw256_init(&ctx_bmw);
	sph_bmw256(&ctx_bmw, hashB, 32);
	sph_bmw256_close(&ctx_bmw, hashA);

	memcpy(state, hashA, 32);
}

struct CHashimotoResult hashimoto(uint8_t *blockToHash, uint32_t *dag, unsigned full_size, int height)
{
    uint64_t n = full_size / HASH_BYTES;
    uint64_t mixhashes = MIX_BYTES / HASH_BYTES;
    uint64_t wordhashes = MIX_BYTES / WORD_BYTES;
    uint8_t header[80];
    uint32_t hashedHeader[8];
    memcpy(header, blockToHash, 80);
    lyra2re2_hash((char *)blockToHash,(char*)hashedHeader, 80);
    uint32_t mix[MIX_BYTES/sizeof(uint32_t)];
    for(int i = 0; i < (MIX_BYTES / HASH_BYTES);i++) {
        memcpy(mix + (i * (HASH_BYTES/sizeof(uint32_t))), hashedHeader, HASH_BYTES);
    }
    for(int i = 0; i < ACCESSES; i++) {
        uint32_t p = fnv(i ^ hashedHeader[0], mix[i % (MIX_BYTES/sizeof(uint32_t))]) % (n / mixhashes) * mixhashes;
        uint32_t newdata[MIX_BYTES/sizeof(uint32_t)];
        for(int j = 0; j < mixhashes; j++) {
            uint64_t pj = (p+j)*8;
            char* item = (char*) dag + pj;
            memcpy(newdata + (j * 8), item, HASH_BYTES);
        }
        for(int i = 0; i < MIX_BYTES/sizeof(uint32_t); i++) {
            mix[i] = fnv(mix[i], newdata[i]);
        }
    }
    uint32_t cmix[4];
    for(int i = 0; i < MIX_BYTES/sizeof(uint32_t); i += 4) {
        cmix[i/4] = fnv(fnv(fnv(mix[i], mix[i+1]), mix[i+2]), mix[i+3]);
    }
    struct CHashimotoResult result;
    memcpy(result.cmix, cmix, MIX_BYTES/4);
    uint8_t hash[52];
    memcpy(hash, hashedHeader, 32);
    memcpy(hash + 36, cmix, 16);
    memcpy(hash + 32, &height, 4);
    lyra2re2_hash((char *)hash, (char *)result.result, 52);
    return result;
}

void generate_dag(int height)
{
    if (first_launch || height % 400 == 0) {
        int epoch = height / 400;
        sph_blake256_context ctx_blake;
        memset(seed, 0, 32);
        for (size_t i = 0; i < height / 400; i++) {
            sph_blake256_init(&ctx_blake);
            sph_blake256(&ctx_blake, seed, 32);
            sph_blake256_close(&ctx_blake, seed);
            //for (uint32_t i = 0; i < 8; i++) {
            //    printf("%08x", ((unsigned int*)seed)[i]);
            //}
            //printf("\n");
            //fflush(stdout);
        }
        cache = (char*)mkcache(get_cache_size(height), (char*)seed);
        dag = (char*)calc_full_dataset((uint32_t*)cache, get_full_size(height), get_cache_size(height), 0, (height / 400));
    }
    first_launch = false;
}
