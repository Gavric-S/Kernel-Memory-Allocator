#include "slab.h"

extern void* space_;
extern int block_num_;

inline unsigned int _get_block_(char* subj) {
	return (subj - (char*)space_) / BLOCK_SIZE;
}

void kmem_init(void *space, int block_num) {
	kmem_init_buddy(space, block_num);
}

kmem_cache_t* kmem_cache_create(const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	return kmem_cache_create_buddy(name, size, ctor, dctor);
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
	int valid_code = is_cache_valid(cachep);
	if (!(valid_code & VALID_OBJECT_CACHE)) return NULL;
	void* ret = NULL;
	if (cachep->slabs_half_full) ret = kmem_cache_alloc_obj(cachep, cachep->slabs_half_full, cachep->ctor);
	else if (cachep->slabs_empty) ret = kmem_cache_alloc_obj(cachep, cachep->slabs_half_full, cachep->ctor);
	else {
		kmem_slab_t* new_slab = kmem_allocate_slab(cachep->slab_size);
		if (!new_slab) return NULL;  // nema mesta za novi slab..
		kmem_init_slab(new_slab, cachep);
		ret = kmem_cache_alloc_obj(cachep, new_slab, cachep->ctor);
	}
	return ret;
}

void kmem_cache_free(kmem_cache_t *cachep, void *objp) {
	int valid_code = is_cache_valid(cachep);
	if (valid_code & VALID_OBJECT_CACHE) return;
	// nadji slab u kom se nalazi
	char* slot_ptr = NULL;
	char found = 0;
	// full obilazak
	kmem_slab_t* current_full = cachep->slabs_full;
	while (current_full) {
		slot_ptr = ((char*)(current_full + 1));
		for (int i = 0; i < current_full->slot_count; i++) {
			if (slot_ptr + current_full->slot_size * i == objp) {
				found = 1;
				break;
			}
		}
		if (found) break;
		current_full = current_full->next;
	}
	// half-full obilazak
	kmem_slab_t* current_half_full = NULL;
	if (!found) {
		current_half_full = cachep->slabs_half_full;
		while (current_half_full) {
			slot_ptr = ((char*)(current_half_full + 1));
			for (int i = 0; i < current_half_full->slot_count; i++) {
				if (slot_ptr + current_half_full->slot_size * i == objp) {
					found = 1;
					break;
				}
			}
			if (found) break;
			current_half_full = current_half_full->next;
		}
	}
	if (found) { // izbaci ga iz slab-a
		if (current_full) { // u punom slab-u
			((void*)slot_ptr) = *((void**)current_full->free); // TODO proveriti obavezno
			current_full->free = ((void*)slot_ptr); //
			current_full->taken_count--;
			// prebacivanje u half-full
			cachep->slabs_full = current_full->next;
			current_full->next = cachep->slabs_half_full;
			cachep->slabs_half_full = current_full;
		}
		else { // u polupunom slab-u
			((void*)slot_ptr) = *((void**)current_half_full->free); // TODO proveriti obavezno
			current_half_full->free = ((void*)slot_ptr); //
			current_half_full->taken_count--;
			// prebacivanje u empty
			if (current_half_full->taken_count == 0) {
				cachep->slabs_half_full = current_half_full->next;
				current_half_full->next = cachep->slabs_empty;
				cachep->slabs_empty = current_half_full;
			}
		}
	}
	// ukoliko nisi nasao slab samo se vrati
	return;
}
 
void* kmalloc(size_t size) {
	int power = maxExponent(size);
	if ((1 << power) != size) return NULL;
	if (power < 5 || power > 17) return NULL;
	char* name = generate_buffer_name(size, power);
	// printf("%s", name);
	// alociranje kesa
	kmem_cache_t* cache_curr = _get_buffer_cache_head_;
	int valid_code = is_cache_valid(cache_curr);
	if (valid_code & NO_BUFFER_CACHE_HEAD) {
		// kreiraj novi kes na mestu cache_head-a...
		// napravi mu jedan slab u koji ces staviti ovaj buffer...

	}
	else if (!(valid_code & VALID_BUFFER_CACHE)) {
		// kreiraj novi kes...
		// napravi mu jedan slab u koji ces staviti ovaj buffer...
	}
	else {
		// stavi bafer u cache...
	}
	return NULL; // treba vratiti ret...
}

void kfree(const void *objp) { // TODO
	kmem_cache_t* cache_curr = _get_buffer_cache_head_;
	int valid_code = is_cache_valid(cache_curr);
	if (valid_code & NO_BUFFER_CACHE_HEAD) return;
	int found = 0;
	char* slot_ptr = NULL;
	while (cache_curr) {
		// if ()...
		kmem_slab_t* current_full = cache_curr->slabs_full;
		slot_ptr = ((char*)(current_full + 1));
		for (int i = 0; i < current_full->slot_count; i++) {
			if (slot_ptr + current_full->slot_size * i == objp) {
				found = 1;
				break;
			}
		}
		if (found) break;
		current_full = current_full->next;
	}
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
