#include "slab.h"

extern void* space_;
extern int block_num_;

inline unsigned int _get_block_(char* subj) { // TODO: sva prilika da je ovo zastarelo..
	return (subj - (char*)space_) / BLOCK_SIZE;
}

void kmem_init(void *space, int block_num) {
	kmem_init_impl(space, block_num);
}

kmem_cache_t* kmem_cache_create(const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	return kmem_cache_create_impl(name, size, ctor, dctor);
}

int kmem_cache_shrink(kmem_cache_t *cachep) {
	return kmem_cache_shrink_impl(cachep);
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

void kfree(const void *objp) {
	kfree_impl(objp);
}

void kmem_cache_destroy(kmem_cache_t *cachep) {
	kmem_cache_destroy_impl(cachep);
}

void kmem_cache_info(kmem_cache_t *cachep) {
	kmem_cache_info_impl(cachep);
}

int kmem_cache_error(kmem_cache_t *cachep) {
	return kmem_cache_error_impl(cachep);
}
