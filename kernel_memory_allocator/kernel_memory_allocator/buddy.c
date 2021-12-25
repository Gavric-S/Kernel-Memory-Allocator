#include "buddy.h"
#include "slab.h"

uint32_t exp_() {
	uint16_t max_buddy_exp = 0;
	while ((1 << max_buddy_exp) < block_num_) max_buddy_exp++;
	uint32_t offset_blocks = (max_buddy_exp * sizeof(buddy_free_t) + sizeof(kmem_cache_t)) / BLOCK_SIZE + 1;
	if ((1 << max_buddy_exp) > block_num_ - offset_blocks) max_buddy_exp--;
	return max_buddy_exp;
}

inline void* avail_space_() {
	uint16_t max_buddy_exp = 0;
	while ((1 << max_buddy_exp) < block_num_) max_buddy_exp++;
	uint32_t offset_blocks = (max_buddy_exp * sizeof(buddy_free_t) + sizeof(kmem_cache_t)) / BLOCK_SIZE + 1;
	return (uint8_t*)space_ + offset_blocks * BLOCK_SIZE;
}

void* kmem_buddy_alloc_mem(uint32_t block_num) {
	if (block_num < 1) return NULL;
	EnterCriticalSection(critical_section_);
	// find exponent for chunk
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	uint16_t i = 0;
	if (!found_free_space(exponent, &i)) {
		LeaveCriticalSection(critical_section_);
		return NULL; // not enough space for allocation
	}

	// try direct allocation (without splitting chunks)
	void* ret = direct_alloc(i, block_num);
	if (ret) {
		LeaveCriticalSection(critical_section_);
		return ret;
	}
	// allocation with splitting
	else ret = disjoin_alloc(i, block_num);

	LeaveCriticalSection(critical_section_);
	return ret;
}

uint32_t kmem_buddy_free_mem(void* target, uint32_t block_num) {
	EnterCriticalSection(critical_section_);
	// add address of target into list
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	if (!chunk_is_valid(target, exponent) || in_list(target, exponent)) {
		LeaveCriticalSection(critical_section_);
		return 0; // invalid chunk (address or size) or already free chunk
	}

	// get buddy of chunk
	void* buddy = get_buddy(target, exponent);
	if (!buddy) { // if no buddy then just free chunk on given address
		attach_to_list(target, exponent);
	}

	// merge free buddy chunks while possible
	uint16_t tmp = 0;
	while (buddy && in_list(buddy, exponent)) {
		// remove buddy chunk from list of free chunks
		detach_from_list(buddy, exponent);
		// if chunk is in list remove him as well
		if (in_list(target, exponent)) detach_from_list(target, exponent);
		// target points to buddy that's 'lower' in memory
		if (target > buddy) target = buddy;
		// add merged buddy chunks into list of bigger chunk pointers
		attach_to_list(target, exponent + 1);
		// get buddy of larger chunk
		buddy = get_buddy(target, exponent + 1);
		exponent++;
		tmp++;
	}

	LeaveCriticalSection(critical_section_);
	return block_num;
}

uint8_t found_free_space(uint16_t exponent, uint16_t* i) {
	for (; *i <= exp_(); (*i)++)
		if (((buddy_free_t*)space_ + *i)->free != NULL && *i >= exponent) return 1;
	return 0;
}

uint32_t addr_offset_bytes(void* addr) {
	uint8_t* relative_mem_start = avail_space_();
	uint8_t* overflow_mem_start = (uint8_t*)avail_space_() + ((1 << exp_()) * BLOCK_SIZE);
	if ((uint8_t*)addr > overflow_mem_start) relative_mem_start = overflow_mem_start; // if address belongs to part of memory after biggest possible 
	// power of two of the buddy system then point the relative_mem_start pointer to address of that part

	return (uint8_t*)addr - (uint8_t*)relative_mem_start;
}

uint8_t chunk_is_in_bounds(void* addr, uint32_t exp) {
	if (addr < space_) return 1;
	if ((uint8_t*)addr + (1 << exp) * BLOCK_SIZE <= (uint8_t*)space_ + block_num_ * BLOCK_SIZE) return 1;
	return 0;
}

uint8_t chunk_is_valid(void* addr, uint32_t exp) {
	// is address even in bounds of memory passed to allocator
	if (!chunk_is_in_bounds(addr, exp)) return 0;

	// is the chunk offset by whole number of blocks in relation to the start of memory passed to allocator
	uint32_t offset_blocks = addr_offset_bytes(addr) / BLOCK_SIZE;
	if (offset_blocks % (1 << exp) != 0) return 0;

	return 1;
}

void* direct_alloc(uint8_t i, uint32_t block_num) {
	if ((1 << i) == block_num || ((1 << i) < (block_num << 1))) {
		void* ret = ((buddy_free_t*)space_ + i)->free;
		((buddy_free_t*)space_ + i)->free = (((buddy_free_t*)space_ + i)->free)->free;
		return ret;
	}
	return NULL;
}

void* disjoin_alloc(uint8_t i, uint32_t block_num) {
	buddy_free_t* lower = NULL;
	while ((1 << i) > block_num && (1 << (i - 1)) >= block_num) {
		lower = ((buddy_free_t*)space_ + i)->free;
		if (!lower) break;
		buddy_free_t* higher = (uint8_t*)(((buddy_free_t*)space_ + i)->free) + (1 << i - 1) * BLOCK_SIZE;
		// sace chain of this level
		((buddy_free_t*)space_ + i)->free = lower->free;
		// add higher
		higher->free = ((buddy_free_t*)space_ + i - 1)->free;
		((buddy_free_t*)space_ + i - 1)->free = higher;
		// add lower
		lower->free = ((buddy_free_t*)space_ + i - 1)->free;
		((buddy_free_t*)space_ + i - 1)->free = lower;
		i--;
	}
	if (!lower) return NULL; // unreachable code due to condition of while loop
	((buddy_free_t*)space_ + i)->free = lower->free;
	return lower;
}

void* get_buddy(void* addr, uint32_t exp) {
	if (exp > exp_()) return NULL;

	uint32_t offset_blocks = addr_offset_bytes(addr) / BLOCK_SIZE;

	void* buddy = NULL;
	if (offset_blocks % (1 << exp) == 0) { // lower buddy
		buddy = (uint8_t*)addr + (1 << exp) * BLOCK_SIZE;
	}
	else { // higher buddy
		buddy = (uint8_t*)addr - (1 << exp) * BLOCK_SIZE;
	}
	if (chunk_is_valid(buddy, exp)) return buddy;
	return NULL;
}

uint8_t in_list(buddy_free_t* buddy, uint32_t exponent) {
	if (!buddy) return 0;

	buddy_free_t* curr = ((buddy_free_t*)space_ + exponent)->free;
	while (curr) {
		if (curr == buddy) return 1;
		curr = curr->free;
	}

	return 0;
}

void detach_from_list(buddy_free_t* target, uint8_t exponent) {
	if (!target) return;
	buddy_free_t* head = ((buddy_free_t*)space_ + exponent);
	if (!head->free) return;

	if (head->free == target) {
		head->free = target->free;
		target->free = NULL;
		return;
	}
	buddy_free_t* prev = head->free, * curr = prev->free;
	while (curr) {
		if (curr == target) {
			prev->free = target->free;
			target->free = NULL;
			return;
		}
		prev = curr;
		curr = curr->free;
	}
}

void attach_to_list(buddy_free_t* target, uint16_t exponent) {
	if (!target) return;
	buddy_free_t* head = ((buddy_free_t*)space_ + exponent);

	target->free = head->free;
	head->free = target;
}

void print_buddy_free_chunk_ptr_list() {
	for (uint32_t i = 0; i <= exp_(); i++) {
		buddy_free_t* curr = ((buddy_free_t*)space_ + i)->free;
		printf("%d: ", i);
		while (curr != NULL) {
			printf("%p\t", curr);
			curr = curr->free;
		}
		if (curr == NULL) printf("NULL!\n");
	}
}

void kmem_init_impl(void *space, uint32_t block_num) {
	if (space < 0 || block_num <= 0) return;
	space_ = space;
	block_num_ = block_num;

	// calculating number of different possible buddy chunk sizes
	uint16_t max_buddy_exp = 0;
	uint16_t leftover_space_blocks;
	while ((1 << max_buddy_exp) < block_num) max_buddy_exp++;

	// offset of space available for buddy allocation in relation to start of memory passed to allocator
	uint32_t offset_bytes = max_buddy_exp * sizeof(buddy_free_t);
	
	// initialization of master cache object
	kmem_cache_init((uint8_t*)space_ + offset_bytes, "MASTER", sizeof(kmem_cache_t), NULL, NULL);
	offset_bytes += sizeof(kmem_cache_t);

	// initialization of global critical section
	CRITICAL_SECTION* critical_section_ptr = (uint8_t*)space_ + offset_bytes;
	InitializeCriticalSectionAndSpinCount(critical_section_ptr, 0x00001000);
	offset_bytes += sizeof(CRITICAL_SECTION);

	uint32_t offset_blocks = offset_bytes / BLOCK_SIZE + (offset_bytes % BLOCK_SIZE) ? 1 : 0;
	block_num -= offset_blocks;
	if ((1 << max_buddy_exp) > block_num) max_buddy_exp--;
	leftover_space_blocks = block_num - (1 << max_buddy_exp);

	// initialization of list of free buddy chunk pointers
	for (uint32_t i = 0; i < max_buddy_exp; i++) ((buddy_free_t*)space_ + i)->free = NULL;
	((buddy_free_t*)space_ + max_buddy_exp)->free = ((buddy_free_t*)avail_space_());
	((buddy_free_t*)avail_space_())->free = NULL;

	// need to update list of free buddy chunk pointers with possible 'overflown' memory
	void* leftover_space_pointer = (uint8_t*)avail_space_() + (1 << max_buddy_exp) * BLOCK_SIZE; // number of leftover blocks
	while (leftover_space_blocks > 0) {
		// calculating exponent of largest power of two for given number of leftover blocks
		uint16_t exponent = 0;
		while ((1 << exponent) < leftover_space_blocks) exponent++;
		if ((1 << exponent) > leftover_space_blocks) exponent--;

		// decrementing number of leftover blocks
		leftover_space_blocks -= (1 << exponent);

		// updating list of free buddy chunk pointers
		((buddy_free_t*)leftover_space_pointer)->free = ((buddy_free_t*)space_ + exponent)->free;
		((buddy_free_t*)space_ + exponent)->free = leftover_space_pointer;
		leftover_space_pointer = (uint8_t*)leftover_space_pointer + (1 << exponent) * BLOCK_SIZE;
	}
}

kmem_cache_t* kmem_cache_create_impl(const uint8_t* name, size_t size, void(*ctor)(void*), void(*dctor)(void*)) {
	if (!name || strlen(name) > MAX_NAME_LENGTH || size < 1) return NULL;

	EnterCriticalSection(&master_cache_addr_->critical_section);
	kmem_cache_t* master_cache_ptr = master_cache_addr_;
	kmem_cache_t* new_cache_ptr = kmem_cache_alloc_impl(master_cache_ptr);
	if (new_cache_ptr) {
		kmem_cache_init(new_cache_ptr, name, size, ctor, dctor);
	}

	LeaveCriticalSection(&master_cache_addr_->critical_section);
	return new_cache_ptr;
}

int kmem_cache_shrink_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) {
		return 0;
	}
	EnterCriticalSection(&cache_ptr->critical_section);

	if (cache_ptr->expanded) {
		cache_ptr->expanded = 0;
		LeaveCriticalSection(&cache_ptr->critical_section);
		return 0;
	}

	int ret = 0;
	if (cache_ptr->slabs_empty) {
		// free all empty slabs
		kmem_slab_t* slab_to_free = cache_ptr->slabs_empty;
		while (slab_to_free) {
			ret += kmem_slab_free(cache_ptr, slab_to_free);
			slab_to_free = cache_ptr->slabs_empty;
		}
		// update fullness percentage
		update_percentage_full(cache_ptr);
	}

	LeaveCriticalSection(&cache_ptr->critical_section);
	return ret;
}

void* kmem_cache_alloc_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	void* object_ptr = NULL;
	if (cache_ptr->slabs_half_full) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_half_full); // half-full slab exists
	else if (cache_ptr->slabs_empty) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_empty); // empty slab exists
	else { // need to allocate new slab
		kmem_slab_t* new_slab = kmem_slab_alloc(cache_ptr);
		if (!new_slab) {
			LeaveCriticalSection(&cache_ptr->critical_section);
			return NULL; // can't allocate new slab
		}
		object_ptr = kmem_cache_alloc_obj(cache_ptr, new_slab);
	}
	// update fullness percentage
	if (object_ptr) update_percentage_full(cache_ptr);

	LeaveCriticalSection(&cache_ptr->critical_section);
	return object_ptr;
}

void kmem_cache_free_impl(kmem_cache_t* cache_ptr, void* object_ptr) {
	if (!cache_ptr || !object_ptr) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	uint8_t found = 0;
	// iterating through half-full slabs
	kmem_slab_t* current_slab = cache_ptr->slabs_half_full;
	while (current_slab) {
		if (object_in_slab(current_slab, object_ptr, cache_ptr->data_size)) {
			found = 1;
			break;
		}
		current_slab = current_slab->next;
	}
	
	if (!current_slab) { // iterating through full slabs
		current_slab = cache_ptr->slabs_full;
		while (current_slab) { 
			if (object_in_slab(current_slab, object_ptr, cache_ptr->data_size)) {
				found = 2;
				break;
			}
			current_slab = current_slab->next;
		}
	}

	if (current_slab) { // slab found
		*((uint8_t*)object_ptr) = SLOT_FREE;
		current_slab->taken_count--;
		if (cache_ptr == master_cache_addr_) DeleteCriticalSection(&((kmem_cache_t*)object_ptr)->critical_section);

		if (current_slab->taken_count == 0) { // slab now empty
			if (!kmem_slab_remove_from_list(current_slab, &cache_ptr->slabs_full))
				kmem_slab_remove_from_list(current_slab, &cache_ptr->slabs_half_full);

			current_slab->next = cache_ptr->slabs_empty;
			cache_ptr->slabs_empty = current_slab;
		}
		else if (current_slab->taken_count == current_slab->slot_count - 1) { // slab was full and is now half-full
			kmem_slab_remove_from_list(current_slab, &cache_ptr->slabs_full);

			current_slab->next = cache_ptr->slabs_half_full;
			cache_ptr->slabs_half_full = current_slab;
		}

		if (cache_ptr->dctor) cache_ptr->dctor(object_ptr); // call destructor for freed object
		update_percentage_full(cache_ptr); // update fullness percentage
	}

	LeaveCriticalSection(&cache_ptr->critical_section);
	return;
}

void* kmalloc_impl(size_t size) {
	uint16_t exponent = exponent_of_two(size);
	if (exponent < 5 || exponent > 17) return NULL;

	uint8_t name[10];
	sprintf(name, "buff-%d", exponent);

	kmem_cache_t* master_cache_ptr = master_cache_addr_;
	EnterCriticalSection(&master_cache_ptr->critical_section);
	kmem_cache_t* buffer_cache_ptr = search_cache_by_name(name);

	if (!buffer_cache_ptr) { // fitting cache not found
		buffer_cache_ptr = kmem_cache_create_impl(name, size, NULL, NULL);
		if (!buffer_cache_ptr) {
			LeaveCriticalSection(&master_cache_ptr->critical_section);
			return NULL; // can't allocate cache
		}
	}

	LeaveCriticalSection(&master_cache_ptr->critical_section);
	return kmem_cache_alloc_impl(buffer_cache_ptr);
}

void kfree_impl(const void* object_ptr) {
	if (!object_ptr) return;
	EnterCriticalSection(&master_cache_addr_->critical_section);

	kmem_cache_t* target_cache_ptr = 0;
	kmem_cache_t* master_cache_ptr = master_cache_addr_;
	kmem_slab_t* master_slab_ptr = master_cache_ptr->slabs_half_full;
	while (!target_cache_ptr && master_slab_ptr) {
		uint32_t taken_found = 0;
		for (uint16_t i = 0; i < master_slab_ptr->slot_count; i++) {
			kmem_cache_t* current_cache_ptr = (kmem_cache_t*)((uint8_t*)(master_slab_ptr + 1) + master_slab_ptr->L1_offset + i * master_slab_ptr->slot_size);
			if ((*(uint8_t*)current_cache_ptr != SLOT_FREE)) {
				taken_found++;
				if (object_in_cache(current_cache_ptr, object_ptr, current_cache_ptr->data_size)) {
					target_cache_ptr = current_cache_ptr;
					break;
				}
			}
			if (taken_found == master_slab_ptr->taken_count) break;
		}
		master_slab_ptr = master_slab_ptr->next;
	}
	master_slab_ptr = master_cache_ptr->slabs_full;
	while (!target_cache_ptr && master_slab_ptr) {
		uint32_t taken_found = 0;
		for (uint16_t i = 0; i < master_slab_ptr->slot_count; i++) {
			kmem_cache_t* current_cache_ptr = (kmem_cache_t*)((uint8_t*)(master_slab_ptr + 1) + master_slab_ptr->L1_offset + i * master_slab_ptr->slot_size);
			if ((*(uint8_t*)current_cache_ptr != SLOT_FREE)) {
				taken_found++;
				if (object_in_cache(current_cache_ptr, object_ptr, current_cache_ptr->data_size)) {
					target_cache_ptr = current_cache_ptr;
					break;
				}
			}
		}
		master_slab_ptr = master_slab_ptr->next;
	}

	LeaveCriticalSection(&master_cache_addr_->critical_section);
	if (target_cache_ptr) kmem_cache_free_impl(target_cache_ptr, object_ptr);
}

void kmem_cache_destroy_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	if (cache_ptr->slabs_half_full || cache_ptr->slabs_full) {
		cache_ptr->error = CACHE_NOT_EMPTY;
		LeaveCriticalSection(&cache_ptr->critical_section);
		return;
	}
	LeaveCriticalSection(&cache_ptr->critical_section);

	kmem_cache_shrink_impl(cache_ptr);

	kmem_cache_free_impl(master_cache_addr_, cache_ptr);
}

void kmem_cache_info_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	printf("[*] %s:\n", cache_ptr->name);
	printf("\tdata size [bytes] = %d\n", cache_ptr->data_size);
	printf("\tcache size [blocks] = %d\n", cache_ptr->slab_count * cache_ptr->blocks_per_slab);
	printf("\tslab count = %d\n", cache_ptr->slab_count);
	printf("\tslots per slab = %d\n", cache_ptr->slots_per_slab);
	printf("\tpercentage full = %.2f%%\n", cache_ptr->percentage_full * 100.0);

	LeaveCriticalSection(&cache_ptr->critical_section);
}

int kmem_cache_error_impl(kmem_cache_t* cache_ptr) {
	EnterCriticalSection(&cache_ptr->critical_section);
	uint8_t code = cache_ptr->error;
	LeaveCriticalSection(&cache_ptr->critical_section);
	return code;
}

void* kmem_cache_alloc_obj(kmem_cache_t* cache_ptr, kmem_slab_t* slab_ptr) {
	uint8_t* addr =  kmem_slab_find_free_slot(slab_ptr);
	*addr = SLOT_TAKEN;
	slab_ptr->taken_count++;

	if (cache_ptr->ctor) cache_ptr->ctor(addr); // call constructor for allocated object

	if (slab_ptr->taken_count == slab_ptr->slot_count) { // slab now full
		// remove slab from old list
		if (!kmem_slab_remove_from_list(slab_ptr, &cache_ptr->slabs_empty)) {
			kmem_slab_remove_from_list(slab_ptr, &cache_ptr->slabs_half_full);
		}
		// insert slab into list of full slabs
		slab_ptr->next = cache_ptr->slabs_full;
		cache_ptr->slabs_full = slab_ptr;
	}
	else if (slab_ptr->taken_count == 1) { // slab now half-full
		// remove slab from old list
		kmem_slab_remove_from_list(slab_ptr, &cache_ptr->slabs_empty);
		// nsert slab into list of half-full slabs
		slab_ptr->next = cache_ptr->slabs_half_full;
		cache_ptr->slabs_half_full = slab_ptr;
	}

	return addr;
}

void kmem_cache_init(kmem_cache_t* cache_ptr, uint8_t* name, size_t data_size, void(*ctor)(void*), void(*dctor)(void*)) {
	if (!cache_ptr || !name || data_size < 1) return;

	for (uint32_t i = 0; i < strlen(name); i++) cache_ptr->name[i] = name[i];
	cache_ptr->name[strlen(name)] = '\0';
	cache_ptr->data_size = data_size;
	cache_ptr->slabs_empty = NULL;
	cache_ptr->slabs_half_full = NULL;
	cache_ptr->slabs_full = NULL;
	cache_ptr->ctor = ctor;
	cache_ptr->dctor = dctor;
	cache_ptr->expanded = 0;
	cache_ptr->slab_count = 0;
	cache_ptr->percentage_full = 0;
	InitializeCriticalSectionAndSpinCount(&cache_ptr->critical_section, 0x00001000);
	cache_ptr->next_L1_offset = 0;
	cache_ptr->error = NO_ERROR;
	
	uint16_t blocks_per_slab = 1;
	while ((blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t) < data_size)) blocks_per_slab *= 2;
	uint16_t best_blocks_per_slab = blocks_per_slab;
	uint16_t best_remainder = (blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t)) % data_size;

	for (uint8_t i = 0; i < 2; i++) {
		blocks_per_slab *= 2;
		uint16_t remainder = (blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t)) % data_size;
		if (remainder < best_remainder) {
			best_remainder = remainder;
			best_blocks_per_slab = blocks_per_slab;
		}
	}

	cache_ptr->blocks_per_slab = best_blocks_per_slab;
	cache_ptr->slots_per_slab = (best_blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t)) / data_size;
}

void kmem_slab_init(kmem_slab_t* slab_ptr, kmem_cache_t* cache_ptr) {
	// initialize fields of given slab
	slab_ptr->slot_size = cache_ptr->data_size;
	slab_ptr->slot_count = cache_ptr->slots_per_slab;
	slab_ptr->taken_count = 0;

	// set L1 offset for given slab
	slab_ptr->L1_offset = cache_ptr->next_L1_offset;

	// update L1 offset for next slab to be allocated for given cache
	if (cache_ptr->next_L1_offset + CACHE_L1_LINE_SIZE > (cache_ptr->blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t) - cache_ptr->data_size * cache_ptr->slots_per_slab))
		cache_ptr->next_L1_offset = 0;
	else cache_ptr->next_L1_offset = cache_ptr->next_L1_offset + CACHE_L1_LINE_SIZE;

	// initialize free slot list
	uint8_t* slot_ptr = (uint8_t*)(slab_ptr + 1) + slab_ptr->L1_offset;
	for (uint32_t i = 0; i < slab_ptr->slot_count; i++) {
		*(slot_ptr + i * slab_ptr->slot_size) = SLOT_FREE;
	}

	// update cache slab lists
	slab_ptr->next = cache_ptr->slabs_empty;
	cache_ptr->slabs_empty = slab_ptr;
	cache_ptr->slab_count++;
}

void* kmem_slab_alloc(kmem_cache_t* cache_ptr) {
	kmem_slab_t* slab_ptr = kmem_buddy_alloc_mem(cache_ptr->blocks_per_slab);
	if (!slab_ptr) { // can't allocate new slab
		cache_ptr->error = NO_MEMORY;
		return NULL;
	}

	kmem_slab_init(slab_ptr, cache_ptr);
	cache_ptr->expanded = 1;

	return slab_ptr;
}

uint32_t kmem_slab_free(kmem_cache_t* cache_ptr, kmem_slab_t* slab_ptr) {
	cache_ptr->slabs_empty = slab_ptr->next;
	cache_ptr->slab_count--;
	uint32_t size_freed = kmem_buddy_free_mem(slab_ptr, cache_ptr->blocks_per_slab);;
	return size_freed;
}

void* search_cache_by_name(const uint8_t* name) {
	if (!name) return NULL;
	kmem_cache_t* master_cache_ptr = master_cache_addr_;

	kmem_slab_t* slab_ptr = master_cache_ptr->slabs_half_full;
	while (slab_ptr) {
		uint8_t* slot_ptr = (uint8_t*)(slab_ptr + 1) + slab_ptr->L1_offset;
		for (uint16_t i = 0; i < slab_ptr->slot_count; i++)
			if (strcmp(((kmem_cache_t*)(slot_ptr + i * master_cache_ptr->data_size))->name, name) == 0) {
				return slot_ptr + i * master_cache_ptr->data_size;
			}
		slab_ptr = slab_ptr->next;
	}
	slab_ptr = master_cache_ptr->slabs_full;
	while (slab_ptr) {
		uint8_t* slot_ptr = (uint8_t*)(slab_ptr + 1) + slab_ptr->L1_offset;
		for (uint16_t i = 0; i < slab_ptr->slot_count; i++)
			if (strcmp(((kmem_cache_t*)(slot_ptr + i * master_cache_ptr->data_size))->name, name) == 0) {
				return slot_ptr + i * master_cache_ptr->data_size;
			}
		slab_ptr = slab_ptr->next;
	}

	return NULL;
}

uint8_t object_in_cache(kmem_cache_t* cache_ptr, void* object_ptr, size_t size) {
	if (!cache_ptr || !object_ptr) return 0;
	if (cache_ptr->data_size != size) return 0;

	EnterCriticalSection(&cache_ptr->critical_section);
	kmem_slab_t* slab_ptr = cache_ptr->slabs_half_full;
	while (slab_ptr) {
		if (object_in_slab(slab_ptr, object_ptr, size)) {
			LeaveCriticalSection(&cache_ptr->critical_section);
			return 1;
		}
		slab_ptr = slab_ptr->next;
	}

	slab_ptr = cache_ptr->slabs_full;
	while (slab_ptr) {
		if (object_in_slab(slab_ptr, object_ptr, size)) {
			LeaveCriticalSection(&cache_ptr->critical_section);
			return 1;
		}
		slab_ptr = slab_ptr->next;
	}

	LeaveCriticalSection(&cache_ptr->critical_section);
	return 0;
}

uint8_t object_in_slab(kmem_slab_t* slab_ptr, void* object_ptr, size_t size) {
	if (!slab_ptr || !object_ptr) return 0;
	if (slab_ptr->slot_size != size) return 0;

	if (!(object_ptr > slab_ptr && object_ptr < (uint8_t*)slab_ptr + sizeof(kmem_slab_t) + slab_ptr->L1_offset + slab_ptr->slot_size * slab_ptr->slot_count)) return 0;
	if (((uint8_t*)object_ptr - ((uint8_t*)slab_ptr + sizeof(kmem_slab_t) + slab_ptr->L1_offset)) % size == 0) return 1;
	return 0;
}

void update_percentage_full(kmem_cache_t* cache_ptr) {
	uint16_t slots_taken = 0;
	
	kmem_slab_t* half_full_slab_ptr = cache_ptr->slabs_half_full;
	while (half_full_slab_ptr) {
		slots_taken += half_full_slab_ptr->taken_count;
		half_full_slab_ptr = half_full_slab_ptr->next;
	}

	kmem_slab_t* full_slab_ptr = cache_ptr->slabs_full;
	while (full_slab_ptr) {
		slots_taken += full_slab_ptr->taken_count;
		full_slab_ptr = full_slab_ptr->next;
	}

	cache_ptr->percentage_full = slots_taken * 1.0 / ((uint64_t)cache_ptr->slab_count * cache_ptr->slots_per_slab);
}

void* kmem_slab_find_free_slot(kmem_slab_t* slab_ptr) {
	uint8_t* slot_ptr = (uint8_t*)(slab_ptr + 1) + slab_ptr->L1_offset;
	for (uint16_t i = 0; i < slab_ptr->slot_count; i++) {
		if (*(slot_ptr + i * slab_ptr->slot_size) == SLOT_FREE) return slot_ptr + i * slab_ptr->slot_size;
	}
	return NULL;
}

uint8_t kmem_slab_remove_from_list(kmem_slab_t* slab_ptr, kmem_slab_t** slabs) {
	kmem_slab_t* current = *slabs, * prev = NULL;
	while (current) {
		if (current == slab_ptr) {
			if (!prev) {
				*slabs = current->next;
			}
			else {
				prev->next = current->next;
			}
			current->next = NULL;
			return 1;
		}
		prev = current;
		current = current->next;
	}

	return 0;
}

uint8_t exponent_of_two(size_t size) {
	if (size < 1) return -1;

	uint8_t valid = 0;
	uint16_t exponent = 0;
	while ((1 << exponent) < size) exponent++;
	return exponent;
}