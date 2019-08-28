#include <stdint.h>

unsigned long get_cache_size(unsigned long block_number);
unsigned long get_full_size(unsigned long block_number);
struct CHashimotoResult hashimoto(uint8_t *blockToHash, uint32_t *dag, unsigned full_size, int height);
uint32_t* mkcache(unsigned long size, char *seed);
uint32_t* calc_dataset_item(uint32_t *cache, unsigned long i, unsigned long cache_size);
uint32_t* calc_full_dataset(uint32_t *cache, unsigned long dataset_size, unsigned long cache_size, int thr_id, uint64_t epoch);
void generate_dag(int height);
