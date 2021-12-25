#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

// buddy chunk - exponent of power of two number of blocks that can be allocated using the buddy system
// splitting of chunk - splitting of chunk into two equally sized smaller buddy chunks

// symbolic constants
#define MAX_NAME_LENGTH (30)
#define MIN_SLOTS_PER_SLAB (64)
#define SLOT_FREE (170)
#define SLOT_TAKEN (85)

// error codes
#define REGULAR (0)
#define NO_MEMORY (1)
#define CACHE_NOT_EMPTY (2)

// global variables, inline functions and macros
void* space_; // start memory address passed to the allocator
uint32_t block_num_; // size of memory space apssed to the allocator

// start address of cache of master cache (cache of caches)
#define master_cache_addr_ ((kmem_cache_t*)((buddy_free_t*)space_ + exp_(block_num_) + 1))
// start address of critical section object
#define critical_section_ ((uint8_t*)((buddy_free_t*)space_ + exp_(block_num_) + 1) + sizeof(kmem_cache_t))

inline uint32_t exp_(); // exponent of power of two blocks that fit into largest possible buddy chunk
inline void* avail_space_(); // start memory address of space available for buddy allocation

// structures
typedef struct buddy_free { // list of free buddy chunks
	struct buddy_free* free;
} buddy_free_t;

typedef struct kmem_slab_s { // slab
	size_t slot_size; // size of slot
	uint32_t slot_count; // number of slots in slab
	uint32_t taken_count; // number of currently taken slots
	uint16_t L1_offset; // offset in relation to L1 line of processor cache
	struct kmem_slab_s* next; // next slab pointer
} kmem_slab_t;

typedef struct kmem_cache_s { // cache
	uint8_t name[MAX_NAME_LENGTH]; // cache name

	kmem_slab_t* slabs_empty; // list of empty slabs
	kmem_slab_t* slabs_half_full; // list of half-full slabs
	kmem_slab_t* slabs_full; // list of full slabs

	void(*ctor)(void *); // cache object constructor
	void(*dctor)(void *); // cache object destructor

	uint8_t expanded; // cache expansion indicator

	size_t data_size; // size of cache object (in bytes)
	uint32_t slab_count; // current allocated slab count
	uint16_t blocks_per_slab; // size of a slab in blocks
	uint32_t slots_per_slab; // number of slots per slab
	float percentage_full; // percentage of cache that's currently taken

	uint16_t next_L1_offset; // offset of next slab to be allocated in relation to L1 line of processor cache

	uint8_t error; // error code of last detected error while working with this cache

	CRITICAL_SECTION critical_section; // critical section of current cache
} kmem_cache_t;

// buddy system functions
// chunk allocation using the buddy system
void* kmem_buddy_alloc_mem(uint32_t);
// chunk deallocation using the buddy system
uint32_t kmem_buddy_free_mem(void*, uint32_t);
// finding the exponent of minimal power of two for which a free chunk can be found
uint8_t found_free_space(uint16_t exponent, uint16_t*);
// calculating offset of given address in relation to start of memory space passed to allocator
uint32_t addr_offset_bytes(void*);
// is the given buddy chunk in bounds of memory passed to allocator
uint8_t chunk_is_in_bounds(void*, uint32_t);
// is the given buddy chunk valid
uint8_t chunk_is_valid(void*, uint32_t);
// direct allocation of chunk
void* direct_alloc(uint8_t, uint32_t);
// allocation of chunk with splitting
void* disjoin_alloc(uint8_t, uint32_t);
// getting buddy chunk of given chunk
void* get_buddy(void*, uint32_t);
// is the given chunk in list of free chunks
uint8_t in_list(buddy_free_t*, uint32_t);
// removing given chunk from list of free chunks
void detach_from_list(buddy_free_t*, uint8_t);
// inserting given chunk into list of free chunks
void attach_to_list(buddy_free_t*, buddy_free_t*);
// printing list of free chunk pointers
void print_buddy_free_chunk_ptr_list();

// implementation of public functions
void kmem_init_impl(void*, uint32_t);
kmem_cache_t* kmem_cache_create_impl(const uint8_t*, size_t, void(*)(void *), void(*)(void *));
int kmem_cache_shrink_impl(kmem_cache_t*);
void* kmem_cache_alloc_impl(kmem_cache_t*);
void kmem_cache_free_impl(kmem_cache_t*, void*);
void* kmalloc_impl(size_t);
void kfree_impl(const void*);
void kmem_cache_destroy_impl(kmem_cache_t*);
void kmem_cache_info_impl(kmem_cache_t*);
int kmem_cache_error_impl(kmem_cache_t*);

// cache and slab functions
// allocation of objects in given slab of given cache
void* kmem_cache_alloc_obj(kmem_cache_t*, kmem_slab_t*);
// initialization of given cache
void kmem_cache_init(kmem_cache_t*, const uint8_t*, size_t, void(*)(void *), void(*)(void *));
// initialization of given slab
void kmem_slab_init(kmem_slab_t*, kmem_cache_t*);
// allocation of a slab
void* kmem_slab_alloc(kmem_cache_t*);
// freeing of a slab
uint32_t kmem_slab_free(kmem_cache_t*, kmem_slab_t*);
// searching for a cache by name
void* search_cache_by_name(const uint8_t*);
// is the given object in the given cache
uint8_t object_in_cache(kmem_cache_t*, void*, size_t);
// is the given object in the given slab
uint8_t object_in_slab(kmem_slab_t*, void*, size_t);
// updating percentage of cache that's currently taken
void update_percentage_full(kmem_cache_t*);
// finding a free slot in the given slab
void* kmem_slab_find_free_slot(kmem_slab_t*);
// removing given slab from given list of slabs
uint8_t kmem_slab_remove_from_list(kmem_slab_t*, kmem_slab_t**);

// helper functions
// calculatingexponent of power of two equal to given number
uint8_t exponent_of_two(size_t);