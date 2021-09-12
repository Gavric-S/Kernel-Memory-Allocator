#include "slab.h"

extern void* space_;
extern int block_num_;

inline unsigned int _get_block_(char* subj) {
	return (subj - (char*)space_) / BLOCK_SIZE;
}

void kmem_init(void *space, int block_num) {
	kmem_init_impl(space, block_num);
}

kmem_cache_t* kmem_cache_create(const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	return kmem_cache_create_impl(name, size, ctor, dctor);
}

int kmem_cache_shrink(kmem_cache_t *cachep) {
	// provera parametra?
	int ret = 0;
	int valid_code = is_cache_valid(cachep);
	if (!(valid_code & VALID_OBJECT_CACHE || valid_code & VALID_BUFFER_CACHE)) return ret; // mozda i -1
	if (cachep->expanded) {
		cachep->expanded = 0;
		return ret;
	}
	kmem_slab_t* to_free = cachep->slabs_empty;
	while (to_free) {
		cachep->slabs_empty = to_free->next;
		ret += kmem_deallocate_slab(to_free);
		cachep->slab_count--;
		to_free = cachep->slabs_empty;
	}
	cachep->expanded = 0;
	return ret;
}

void* kmem_cache_alloc(kmem_cache_t *cachep) {
	return kmem_cache_alloc_impl(cachep);
}

void kmem_cache_free(kmem_cache_t *cachep, void *objp) {
	kmem_cache_free_impl(cachep, objp);
}
 
void* kmalloc(size_t size) {
	kmalloc_impl(size);
}

void kfree(const void *objp) { // TODO
	kfree_impl(objp);
}

void kmem_cache_destroy(kmem_cache_t *cachep) {
	int valid_code = is_cache_valid(cachep);
	if (!(valid_code & VALID_OBJECT_CACHE || valid_code & VALID_BUFFER_CACHE)) return;
	if (valid_code & VALID_OBJECT_CACHE) { // object cache

	}
	else { // buffer cache

	}
}

void kmem_cache_info(kmem_cache_t *cachep) {
	int valid_code = is_cache_valid(cachep);
	if (!(valid_code & VALID_OBJECT_CACHE || valid_code & VALID_BUFFER_CACHE)) {
		printf("Invalid cache...\n");
		return;
	}
	// ili cu ovde proci kroz sve slab-ove da bih izracunao sve ove promenljive - ovo je svakako bolje zbog procenta rekao bih
	// ili cu imati sve ove vrednosti u samom cache-u pa cu ih stalno azurirati
	int cache_size = 0;
	int slab_count = 0;
	int taken_count = 0;
	// iteriranje kroz empty
	kmem_slab_t* current_empty = cachep->slabs_empty;
	// TODO iz ovoga se zakljucuje da bi slot_count i slot_size trebali da budu samo u kesu a da slab ima pokazivac na kes!!!
	while (current_empty) {
		cache_size += (current_empty->slot_count * current_empty->slot_size + sizeof(kmem_slab_t)) / BLOCK_SIZE;
		slab_count++;
		current_empty = current_empty->next;
	}
	// TODO iz ovoga se zakljucuje da bi slot_count i slot_size trebali da budu samo u kesu a da slab ima pokazivac na kes!!!
	// iteriranje kroz half-full
	kmem_slab_t* current_half_full = cachep->slabs_half_full;
	while (current_half_full) {
		cache_size += (current_half_full->slot_count * current_half_full->slot_size + sizeof(kmem_slab_t)) / BLOCK_SIZE;
		slab_count++;
		taken_count += current_half_full->taken_count;
		current_half_full = current_half_full->next;
	}
	// iteriranje kroz full
	kmem_slab_t* current_full = cachep->slabs_full;
	while (current_full) {
		cache_size += (current_full->slot_count * current_full->slot_size + sizeof(kmem_slab_t)) / BLOCK_SIZE;
		slab_count++;
		taken_count += current_full->taken_count;
		current_full = current_full->next;
	}
	float perc = (float)taken_count / (slab_count * cachep->slot_count) * 100;
	printf("[*] %s:\n", cachep->name);
	printf("\tdata size = %d\n", cachep->data_size);
	printf("\tcache size = %d\n", cache_size);
	printf("\tslab count = %d\n", slab_count);
	printf("\tdata size = %d\n", cachep->data_size);
	printf("\tslots per slab = %d\n", cachep->slot_count);
	printf("\tdata size = %f.2%%\n", perc);
	return;
}

int kmem_cache_error(kmem_cache_t *cachep) {
	int valid_code = is_cache_valid(cachep);
	if (!(valid_code & VALID_OBJECT_CACHE || valid_code & VALID_BUFFER_CACHE)) return -1;

	return 0;
}
