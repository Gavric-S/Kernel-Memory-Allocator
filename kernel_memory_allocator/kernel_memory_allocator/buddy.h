#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NO_OBJECT_CACHE_HEAD 1
#define NO_BUFFER_CACHE_HEAD 4
#define VALID_OBJECT_CACHE 8
#define VALID_BUFFER_CACHE 16
#define INVALID_CACHE 32

void* space_;
// void* avail_space_;
uint32_t block_num_;
// short exp_;

inline uint32_t exp_();
inline void* avail_space_();

typedef struct buddy_free {
	struct buddy_free* free; // moze biti i void* videcemo
} buddy_free_t;

typedef struct kmem_slab_s {
	uint32_t slot_size;
	uint32_t slot_count; // nesto od ova dva mozda visak
	uint32_t taken_count;
	void* free;
	struct kmem_slab_s* next;
} kmem_slab_t;

typedef struct kmem_cache_s {
	uint8_t name[30];
	size_t data_size;
	kmem_slab_t* slabs_empty;
	kmem_slab_t* slabs_half_full;
	kmem_slab_t* slabs_full;
	void(*ctor)(void *);
	void(*dctor)(void *);
	uint8_t expanded;
	// nesto od ovoga ispod je verovatno visak... (oznaceni sa //.)
	// TODO treba azurirati atribute prilikom dodavanja/oduzimanja slab-ova
	uint32_t blk_count; //.
	uint32_t slab_count;
	uint16_t slab_size;
	uint32_t slot_count; // po ploci
	float perc_full; //.
	struct kmem_cache_s* next_cache;
	struct kmem_cache_s* prev_cache;
} kmem_cache_t;

#define master_cache_ (kmem_cache_t*)((buddy_free_t*)space_ + exp_(block_num_) + 1) // TODO: proveriti
//#define _get_buffer_cache_head_ (kmem_cache_t*)(((buddy_free_t*)space_ + exp_(block_num_) + 1)) + 1

extern inline uint32_t _get_block_(uint8_t* subj);

void kmem_init_impl(void *space, uint32_t block_num);
kmem_cache_t* kmem_cache_create_impl(const uint8_t*name, size_t size, void(*ctor)(void *), void(*dctor)(void *));
void* kmem_buddy_alloc_mem(uint32_t block_num);
uint32_t kmem_buddy_dealloc_mem(void* addr, uint32_t block_num); // povratna vrednost?

// implementacija kmem_cache_alloc
void* kmem_cache_alloc_impl(kmem_cache_t*);
// implementacija kmem_cache_free
void kmem_cache_free_impl(kmem_cache_t*, void*);
// implementacija kmalloc
void* kmalloc_impl(size_t size);
// implementacija kfree
void kfree_impl(const void* objp);

// ove dve mozda ne moraju ni da postoje
/*void* kmem_allocate_slab(size_t size);*/ // parametri?
uint32_t kmem_deallocate_slab(kmem_slab_t* target); // povratna vrednost?

void* kmem_cache_alloc_obj(kmem_cache_t* cache, kmem_slab_t* slab, void(*ctor)(void *));


// helpers:
// inicijalizacija cache-a
void kmem_cache_init(kmem_cache_t* cache, const uint8_t*name, size_t size, void(*ctor)(void *), void(*dctor)(void *));
// inicijalizacija slab-a
void kmem_slab_init(kmem_slab_t* slabp, kmem_cache_t* cachep);

uint32_t is_cache_valid(kmem_cache_t* cache);

const uint8_t* generate_buffer_name(size_t size, uint32_t N);

uint8_t found_free_space(uint16_t, uint16_t*);

uint16_t max_exp(uint32_t block_num);

uint32_t addr_offset_bytes(void*);
uint8_t chunk_is_in_bounds(void*, uint32_t);
uint8_t chunk_buddy_is_valid(void*, uint32_t);

void* direct_alloc(uint8_t, uint32_t);
void* disjoin_alloc(uint8_t, uint32_t);

void* get_buddy(void*, uint32_t);

uint8_t in_list(buddy_free_t*, uint32_t);
void detach_from_list(buddy_free_t*, uint8_t);
void attach_to_list(buddy_free_t*, buddy_free_t*);

void print_buddy_ptr_list();

void* search_by_cache_name(kmem_cache_t* cache, char* name);