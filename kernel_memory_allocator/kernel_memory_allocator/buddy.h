#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

// buddy chunk - stepen dvojke broj blokova koje je moguce alocirati buddy sistemom
// cepanje chunk-a - deljenje chunk-a na dva jednaka chunk-a parnjaka

/* simbolicke konstante */
#define MAX_NAME_LENGTH 30
#define MIN_SLOTS_PER_SLAB 64
#define SLOT_FREE (170)
#define SLOT_TAKEN 85

// kodovi gresaka
#define NO_ERROR 0
#define NO_MEMORY 1
#define CACHE_NOT_EMPTY 2

/* globalne promenljive, makroi i inline funkcije */
void* space_; // pocetak prostora za kmem allocator
uint32_t block_num_; // velicina prostora za kmem allocator u blokovima

// adresa cache-a cache-eva
#define master_cache_addr_ ((kmem_cache_t*)((buddy_free_t*)space_ + exp_(block_num_) + 1))
// objekat kriticne sekcije
#define critical_section_ ((uint8_t*)((buddy_free_t*)space_ + exp_(block_num_) + 1) + sizeof(kmem_cache_t))

inline uint32_t exp_(); // najveci stepen velicine buddy parnjaka
inline void* avail_space_(); // pocetak prostora raspolozivog za buddy alokaciju

/* strukture */
typedef struct buddy_free { // lista slobodnih buddy parnjaka
	struct buddy_free* free;
} buddy_free_t;

typedef struct kmem_slab_s { // slab
	size_t slot_size; // velicina slot-a
	uint32_t slot_count; // broj slot-ova
	uint32_t taken_count; // broj zauzetih slot-ova
/*	void* free;*/ // problem oko slucaja kada je sama velicina free pokazivaca veca od slot-a moze se resiti tako sto bi min slot_size bio 4B
	uint16_t L1_offset;
	struct kmem_slab_s* next; // sledeci slab
} kmem_slab_t;

typedef struct kmem_cache_s { // cache
	uint8_t name[MAX_NAME_LENGTH]; // ime cache-a

	kmem_slab_t* slabs_empty; // lista praznih slab-ova
	kmem_slab_t* slabs_half_full; // lista polupunih slab-ova
	kmem_slab_t* slabs_full; // lista punih slab-ova

	void(*ctor)(void *); // konstruktor objekata cache-a
	void(*dctor)(void *); // destruktor objekata cache-a

	uint8_t expanded; // indikator prosirenja cache-a

	size_t data_size; // velicina jednog objekta cache-a
	uint32_t slab_count; // trenutni broj slab-ova
	uint16_t blocks_per_slab; // broj blokova koje jedan slab zauzima
	uint32_t slots_per_slab; // broj slotova po slab-u
	float percentage_full; // trenutni procenat popunjenosti cache-a

	uint16_t next_L1_offset;

	uint8_t error; // kod poslednje greske prilikom rada sa cache-om

	CRITICAL_SECTION critical_section; // kriticna sekcija za dati cache
} kmem_cache_t;

/* buddy funkcije */
// alokacija chunk-a pomocu buddy sistema
void* kmem_buddy_alloc_mem(uint32_t);
// dealokacija chunk-a pomocu buddy sistema
uint32_t kmem_buddy_free_mem(void*, uint32_t);
// pronalazak prvog eksponenta za koga postoje slobodni chunk-ovi u buddy sistemu
uint8_t found_free_space(uint16_t exponent, uint16_t*);
// racunanje offset-a date adrese od pocetka prostora u bajtovima
uint32_t addr_offset_bytes(void*);
// da li je dati buddy chunk u okviru memorije
uint8_t chunk_is_in_bounds(void*, uint32_t);
// da li je dati buddy chunk validan
uint8_t chunk_is_valid(void*, uint32_t);
// direktna alokacija chunk-a
void* direct_alloc(uint8_t, uint32_t);
// alokacija sa cepanjem chunk-ova
void* disjoin_alloc(uint8_t, uint32_t);
// dohvatanje parnjaka za dati chunk
void* get_buddy(void*, uint32_t);
// provera da li je dati chunk u listi slobodnih
uint8_t in_list(buddy_free_t*, uint32_t);
// uklanjanje datog chunk-a iz liste slobodnih
void detach_from_list(buddy_free_t*, uint8_t);
// ubacivanje datog chunk-a u listu slobodnih
void attach_to_list(buddy_free_t*, buddy_free_t*);
// stampanje liste pokazivaca na slobodne chunk-ove
void print_buddy_free_chunk_ptr_list();

/* implementacije javnih funkcija */ 
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

/* cache i slab funkcije */
// alokacija objekta u datom slab-u datog cache-a
void* kmem_cache_alloc_obj(kmem_cache_t*, kmem_slab_t*);
// inicijalizacija cache-a
void kmem_cache_init(kmem_cache_t*, const uint8_t*, size_t, void(*)(void *), void(*)(void *));
// inicijalizacija slab-a
void kmem_slab_init(kmem_slab_t*, kmem_cache_t*);
// alokacija slab-a
void* kmem_slab_alloc(kmem_cache_t*);
// oslobadjanje slab-a
uint32_t kmem_slab_free(kmem_cache_t*, kmem_slab_t*);
// pretraga cache-a po imenu
void* search_cache_by_name(const uint8_t*);
// provera da li je objekat u cache-u
uint8_t object_in_cache(kmem_cache_t*, void*, size_t);
// provera da li je objekat u slab-u
uint8_t object_in_slab(kmem_slab_t*, void*, size_t);
// azuriranje procenta popunjenosti cache-a
void update_percentage_full(kmem_cache_t*);
// pronalazak slobodnog slot-a u slab-u
void* kmem_slab_find_free_slot(kmem_slab_t*);
// uklanjanje slab-a iz liste slab-ova
uint8_t kmem_slab_remove_from_list(kmem_slab_t*, kmem_slab_t**);

/* helper-i */
// racunanje eksponenta stepena dvojke koji je jednak datom broju
uint8_t exponent_of_two(size_t);