#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define NO_OBJECT_CACHE_HEAD 1
#define NO_BUFFER_CACHE_HEAD 4
#define VALID_OBJECT_CACHE 8
#define VALID_BUFFER_CACHE 16
#define INVALID_CACHE 32

void* space_;
void* avail_space_;
int block_num_;
short exp_;

typedef struct buddy_free {
	struct buddy_free* free; // moze biti i void* videcemo
} buddy_free_t;

typedef struct kmem_slab_s {
	int slot_size;
	int slot_count; // nesto od ova dva mozda visak
	int taken_count;
	void* free;
	struct kmem_slab_s* next;
} kmem_slab_t;

typedef struct kmem_cache_s {
	char* name;
	size_t data_size;
	kmem_slab_t* slabs_empty;
	kmem_slab_t* slabs_half_full;
	kmem_slab_t* slabs_full;
	void(*ctor)(void *);
	void(*dctor)(void *);
	char expanded;
	// nesto od ovoga ispod je verovatno visak... (oznaceni sa //.)
	// TODO treba azurirati atribute prilikom dodavanja/oduzimanja slab-ova
	int blk_count; //.
	int slab_count;
	size_t slab_size;
	int slot_count; // po ploci
	float perc_full; //.
	struct kmem_cache_s* next_cache;
	struct kmem_cache_s* prev_cache;
} kmem_cache_t;

#define _get_object_cache_head_ (kmem_cache_t*)((buddy_free_t*)space_ + maxExponent(block_num_) + 1)
#define _get_buffer_cache_head_ (kmem_cache_t*)(((buddy_free_t*)space_ + maxExponent(block_num_) + 1)) + 1

extern inline unsigned int _get_block_(char* subj);

void kmem_init_buddy(void *space, int block_num);
kmem_cache_t* kmem_cache_create_buddy(const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *));
void* kmem_buddy_alloc_mem(int block_num);
int kmem_buddy_dealloc_mem(void* addr, int block_num); // povratna vrednost?

// ove dve mozda ne moraju ni da postoje
void* kmem_allocate_slab(size_t size); // parametri?
int kmem_deallocate_slab(kmem_slab_t* target); // povratna vrednost?

void* kmem_cache_alloc_obj(kmem_cache_t* cache, kmem_slab_t* slab, void(*ctor)(void *));

// helpers:
unsigned short maxExponent(int block_num);
void kmem_init_cache(kmem_cache_t* cache, const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *));
void kmem_init_slab(kmem_slab_t* slabp, kmem_cache_t* cachep);
int is_cache_valid(kmem_cache_t* cache);
const char* generate_buffer_name(size_t size, int N);

char found_free_space(unsigned short, short*);
void* direct_alloc(char, int);
void* disjoin_alloc(char, int);

void* get_buddy(void*, int);
char is_valid_addr(void*, int);
char in_list(buddy_free_t*, int);
void detach_from_list(buddy_free_t*, char);
void attach_to_list(buddy_free_t*, buddy_free_t*);
void print_buddy_ptr_list();
