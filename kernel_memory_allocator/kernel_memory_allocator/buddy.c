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

	// izracunaj eksponent chunk-a
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	uint16_t i = 0;
	if (!found_free_space(exponent, &i)) return NULL; // nema slobodnog prostora za alokaciju

	// pokusaj direktne alokacije(bez cepanja chunk-ova)
	void* ret = direct_alloc(i, block_num);
	if (ret) {
		return ret;
	}
	// alokacija sa cepanjem
	else ret = disjoin_alloc(i, block_num);

	// TODO: ukloniti
	printf("alocirana memorija.\n");
	printf("adresa: %p\n", ret);
	print_buddy_free_chunk_ptr_list();
	return ret;
}

uint32_t kmem_buddy_free_mem(void* target, uint32_t block_num) {
	// dodaj adresu mete u listu
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	if (!chunk_buddy_is_valid(target, exponent)) return 0; // invalidan chunk (adresa ili velicina)
	if (in_list(target, exponent)) return 0; // vec slobodan chunk

	// dohvati parnjaka:
	void* buddy = get_buddy(target, exponent);
	if (!buddy) { // ukoliko nema parnjaka samo oslobodi chunk na datoj adresi
		attach_to_list(((buddy_free_t*)space_ + exponent), target);
	}

	// spajaj slobodne parnjake dok god mozes
	while (buddy && in_list(buddy, exponent)) {
		// izbacivanje parnjaka iz liste slobodnih chunk-ova
		detach_from_list(buddy, exponent);
		// ukoliko je chunk u listi i on se izbacuje
		if (in_list(target, exponent)) detach_from_list(target, exponent);
		// target pokazuje na nizeg parnjaka
		if (target > buddy) target = buddy;
		// dodavanje spojenih parnjaka u listu pokazivaca na vece chunk-ove
		attach_to_list(((buddy_free_t*)space_ + exponent + 1), target);
		// dohvati parnjaka veceg chunk-a
		buddy = get_buddy(target, exponent + 1);
		exponent++;
	}

	// TODO: ukloniti
	printf("dealocirana memorija.\n");
	print_buddy_free_chunk_ptr_list();
	return block_num;
}

uint8_t found_free_space(uint16_t exponent, uint16_t* i) {
	for (; *i <= exp_(); (*i)++)
		if (((buddy_free_t*)space_ + *i)->free != NULL && *i >= exponent) return 1;
	return 0;
}

uint32_t offset_bytes(void* addr) {
	uint8_t* relative_mem_start = avail_space_();
	uint8_t* overflow_mem_start = (uint8_t*)avail_space_() + ((1 << exp_()) * BLOCK_SIZE);
	if ((uint8_t*)addr > overflow_mem_start) relative_mem_start = overflow_mem_start; // ukoliko adresa pripada delu memorije posle najveceg-
	// stepena buddy sistema pomeri relativni pocetak memorije na taj deo

	return (uint8_t*)addr - (uint8_t*)relative_mem_start;
}

uint8_t chunk_is_in_bounds(void* addr, uint32_t exp) {
	if (addr < space_) return 1;
	if ((uint8_t*)addr + (1 << exp) * BLOCK_SIZE <= (uint8_t*)space_ + block_num_ * BLOCK_SIZE) return 1;
	return 0;
}

uint8_t chunk_buddy_is_valid(void* addr, uint32_t exp) {
	// da li je adresa uopste u okviru memorije
	if (!chunk_is_in_bounds(addr, exp)) return 0;

	// da li je udaljen ceo broj blokova stepenovanih eksponentom od pocetka memorije
	uint32_t offset_blocks = offset_bytes(addr) / BLOCK_SIZE;
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
		buddy_free_t* higher = (((uint8_t*)(((buddy_free_t*)space_ + i)->free)) + (1 << i - 1) * BLOCK_SIZE);
		// sacuvaj lanac ovog nivoa
		((buddy_free_t*)space_ + i)->free = lower->free;
		// smestimo higher
		higher->free = ((buddy_free_t*)space_ + i - 1)->free;
		((buddy_free_t*)space_ + i - 1)->free = higher;
		// smestimo lower
		lower->free = ((buddy_free_t*)space_ + i - 1)->free;
		((buddy_free_t*)space_ + i - 1)->free = lower;
		i--;
	}
	if (!lower) return NULL; // ovaj slucaj nije moguc zbog prethodnih provera
	else ((buddy_free_t*)space_ + i)->free = lower->free;
	return lower;
}

void* get_buddy(void* addr, uint32_t exp) {
	if (exp > exp_()) return NULL;

	uint32_t offset_blocks = offset_bytes(addr) / BLOCK_SIZE;

	void* buddy = NULL;
	if (offset_blocks % (1 << exp) == 0) { // ja sam donji parnjak
		buddy = (uint8_t*)addr + (1 << exp) * BLOCK_SIZE;
	}
	else { // ja sam gornji parnjak
		buddy = (uint8_t*)addr - (1 << exp) * BLOCK_SIZE;
	}
	if (chunk_is_in_bounds(buddy, exp)) return buddy;
	return NULL;
}

uint8_t in_list(buddy_free_t* buddy, uint32_t exponent) {
	buddy_free_t* curr = ((buddy_free_t*)space_ + exponent)->free;
	while (curr) {
		if (curr == buddy) return 1;
		curr = curr->free;
	}
	return 0;
}

void detach_from_list(buddy_free_t* target, uint8_t exponent) {
	buddy_free_t* head = ((buddy_free_t*)space_ + exponent);
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
		}
		prev = curr;
		curr = curr->free;
	}
}

void attach_to_list(buddy_free_t* head, buddy_free_t* target) {
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

	// racunanje broja razlicitih mogucih velicina buddy chunk-ova
	uint16_t max_buddy_exp = 0;
	uint16_t leftover_space_blocks;
	while ((1 << max_buddy_exp) < block_num) max_buddy_exp++;

	// offset od pocetka dodeljene memorije od kog pocinje prostor raspoloziv za buddy alokaciju
	uint32_t offset_bytes = max_buddy_exp * sizeof(buddy_free_t);
	
	// inicijalizacija master cache objekta:
	kmem_cache_init((uint8_t*)space_ + offset_bytes, "CACHES", sizeof(kmem_cache_t), NULL, NULL);
	offset_bytes += sizeof(kmem_cache_t);

	// inicijalizacija kriticne sekcije
	//CRITICAL_SECTION* critical_section_ptr = (uint8_t*)space_ + offset_bytes;
	//InitializeCriticalSectionAndSpinCount(critical_section_ptr, 0x00000400);
	//offset_bytes += sizeof(CRITICAL_SECTION);

	uint32_t offset_blocks = offset_bytes / BLOCK_SIZE + (offset_bytes % BLOCK_SIZE) ? 1 : 0;
	block_num -= offset_blocks;
	if ((1 << max_buddy_exp) > block_num) max_buddy_exp--;
	// exp_ = free_buddy_length;
	leftover_space_blocks = block_num - (1 << max_buddy_exp);

	// avail_space_ = (uint8_t*)space + offset_blocks * BLOCK_SIZE;

	// inicijalizacija listi pokazivaca na slobodne chunk-ove buddy sistema
	for (uint32_t i = 0; i < max_buddy_exp; i++) ((buddy_free_t*)space_ + i)->free = NULL;
	((buddy_free_t*)space_ + max_buddy_exp)->free = ((buddy_free_t*)avail_space_());
	((buddy_free_t*)avail_space_())->free = NULL;

	// cepanje memorije koja se nalazi van maksimalnog stepena dvojke za buddy sistem i azuriranje liste pokazivaca
	// tako da pokazuju na nju
	void* leftover_space_pointer = (uint8_t*)avail_space_() + (1 << max_buddy_exp) * BLOCK_SIZE; // kolicina preostalih blokova
	while (leftover_space_blocks > 0) {
		// racunanje maksimalnog eksponenta dvojke za datu kolicinu preostalih blokova
		uint16_t exponent = 0;
		while ((1 << exponent) < leftover_space_blocks) exponent++;
		if ((1 << exponent) > leftover_space_blocks) exponent--;

		// umanjivanje kolicine preostalih blokova
		leftover_space_blocks -= (1 << exponent);

		// azuriranje pokazivaca na slobodnu memoriju tako da pokriju date preostale blokove
		((buddy_free_t*)leftover_space_pointer)->free = ((buddy_free_t*)space_ + exponent)->free;
		((buddy_free_t*)space_ + exponent)->free = leftover_space_pointer;
		leftover_space_pointer = (uint8_t*)leftover_space_pointer + (1 << exponent) * BLOCK_SIZE;
	}
}

kmem_cache_t* kmem_cache_create_impl(const uint8_t* name, size_t size, void(*ctor)(void*), void(*dctor)(void*)) {
	if (!name || strlen(name) > MAX_NAME_LENGTH || size < 1) return NULL;

	kmem_cache_t* master_cache_ptr = master_cache_addr_;
	void* new_cache_ptr = kmem_cache_alloc_impl(master_cache_ptr);
	if (new_cache_ptr) kmem_cache_init(new_cache_ptr, name, size, ctor, dctor);
	return new_cache_ptr;
}

int kmem_cache_shrink_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) {
		return 0;
	}
	EnterCriticalSection(&cache_ptr->critical_section);

	if (cache_ptr != master_cache_addr_ && !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t))) {
		LeaveCriticalSection(&cache_ptr->critical_section);
		return;
	}

	if (cache_ptr->expanded) {
		cache_ptr->expanded = 0;
		LeaveCriticalSection(&cache_ptr->critical_section);
		return 0;
	}

	int ret = 0;
	if (cache_ptr->slabs_empty) {
		// oslobadjanje svih praznih slab-ova
		kmem_slab_t* slab_to_free = cache_ptr->slabs_empty;
		while (slab_to_free) {
			ret += kmem_slab_free(cache_ptr, slab_to_free);
			slab_to_free = cache_ptr->slabs_empty;
		}
		// azuriranje procenta popunjenosti
		update_percentage_full(cache_ptr);
	}

	LeaveCriticalSection(&cache_ptr->critical_section);
	return ret;
}

void* kmem_cache_alloc_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr || (cache_ptr != master_cache_addr_ && !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t)))) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	void* object_ptr = NULL;
	if (cache_ptr->slabs_half_full) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_half_full); // postoji polupopunjen slab
	else if (cache_ptr->slabs_empty) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_half_full); // postoji prazan slab
	else { // potrebno alocirati novi slab
		kmem_slab_t* new_slab = kmem_slab_alloc(cache_ptr);
		if (!new_slab) {
			LeaveCriticalSection(&cache_ptr->critical_section);
			return NULL; // nemoguce alocirati slab trenutno
		}
		object_ptr = kmem_cache_alloc_obj(cache_ptr, new_slab);
	}
	// azuriranje procenta popunjenosti
	if (object_ptr) update_percentage_full(cache_ptr);

	LeaveCriticalSection(&cache_ptr->critical_section);
	return object_ptr;
}

void kmem_cache_free_impl(kmem_cache_t* cache_ptr, void* object_ptr) {
	if (!cache_ptr || !object_ptr) return;
	if (cache_ptr != master_cache_addr_ && !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t))) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	uint8_t found = 0;
	// obilazak polupunih slab-ova
	kmem_slab_t* current_half_full = cache_ptr->slabs_half_full;
	while (current_half_full) {
		if (object_in_slab(current_half_full, object_ptr, cache_ptr->data_size)) {
			found = 1;
			break;
		}
		current_half_full = current_half_full->next;
	}

	// obilazak punih slab-ova
	kmem_slab_t* current_full = cache_ptr->slabs_full;
	if (!found) {
		while (current_full) {
			if (object_in_slab(current_full, object_ptr, cache_ptr->data_size)) {
				found = 2;
				break;
			}
			current_full = current_full->next;
		}
	}

	if (found == 1) { // u polupunom slab-u
		*(void**)(object_ptr) = current_half_full->free;
		current_half_full->free = object_ptr;
		current_half_full->taken_count--;

		if (current_half_full->taken_count == 0) { // ukoliko poslednji popunjeni slot prebacivanje u empty
			cache_ptr->slabs_half_full = current_half_full->next;
			current_half_full->next = cache_ptr->slabs_empty;
			cache_ptr->slabs_empty = current_half_full;
		}
	}
	else if (found == 2) { // u punom slab-u 
		*(void**)(object_ptr) = current_full->free;
		current_full->free = object_ptr;
		current_full->taken_count--;

		// prebacivanje slab-a u polupune
		cache_ptr->slabs_full = current_full->next;
		current_full->next = cache_ptr->slabs_half_full;
		cache_ptr->slabs_half_full = current_full;
	}
	if (found) {
		if (cache_ptr->dctor) cache_ptr->dctor(object_ptr); // pozivanje destruktora za oslobodjeni objekat
		update_percentage_full(cache_ptr); // azuriranje procenta popunjenosti cache-a
	}

	LeaveCriticalSection(&cache_ptr->critical_section);
	return;
}

void* kmalloc_impl(size_t size) {
	uint16_t exponent = exponent_of_two(size);
	if (exponent < 5 || exponent > 17) return NULL;

	uint8_t name[10];
	sprintf(name, "buff-%d", exponent);

	kmem_cache_t* buffer_cache_ptr = search_cache_by_name(name);

	if (!buffer_cache_ptr) { // ne postoji odgovarajuci cache
		buffer_cache_ptr = kmem_cache_create_impl(name, size, NULL, NULL);
		if (!buffer_cache_ptr) return NULL; // cache ne moze trenutno da se alocira
	}

	return kmem_cache_alloc_impl(buffer_cache_ptr);
}

void kfree_impl(const void* object_ptr) {
	if (!object_ptr) return;

	kmem_cache_t* master_cache_ptr = master_cache_addr_;
	kmem_slab_t* master_slab_ptr = master_cache_ptr->slabs_half_full;
	while (master_slab_ptr) {
		for (uint16_t i = 0; i < master_slab_ptr->slot_count; i++) {
			kmem_cache_t* current_cache = (kmem_cache_t*)((uint8_t*)(master_slab_ptr + 1) + i * master_slab_ptr->slot_size);
			if (object_in_cache(current_cache, object_ptr, current_cache->data_size)) {
				kmem_cache_free_impl(current_cache, object_ptr);
				return;
			}
		}
		master_slab_ptr = master_slab_ptr->next;
	}
	master_slab_ptr = master_cache_ptr->slabs_full;
	while (master_slab_ptr) { // TODO - optimalnije implementirati
		for (uint16_t i = 0; i < master_slab_ptr->slot_count; i++) {
			kmem_cache_t* current_cache = (kmem_cache_t*)((uint8_t*)(master_slab_ptr + 1) + i * master_slab_ptr->slot_size);
			if (object_in_cache(current_cache, object_ptr, current_cache->data_size)) {
				kmem_cache_free_impl(current_cache, object_ptr);
				return;
			}
		}
		master_slab_ptr = master_slab_ptr->next;
	}
}

void kmem_cache_destroy_impl(kmem_cache_t* cache_ptr) { // unistiti samo ako je prazno... TODO (ne postoji nijedna half-full ili full ploca
	if (!cache_ptr || cache_ptr == master_cache_addr_ || !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t))) return;
	EnterCriticalSection(&cache_ptr->critical_section);

	if (cache_ptr->slabs_half_full || cache_ptr->slabs_full) {
		cache_ptr->error = CACHE_NOT_EMPTY;
		LeaveCriticalSection(&cache_ptr->critical_section);
		return;
	}

	kmem_cache_shrink_impl(cache_ptr);

	// TODO mozda wrap
	DeleteCriticalSection(&cache_ptr->critical_section);
	kmem_cache_free_impl(master_cache_addr_, cache_ptr);

	LeaveCriticalSection(&cache_ptr->critical_section);
}

void kmem_cache_info_impl(kmem_cache_t* cache_ptr) {
	if (!cache_ptr) return;
	if (cache_ptr != master_cache_addr_ && !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t))) return;
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
	if (!cache_ptr || cache_ptr == master_cache_addr_ || !object_in_cache(master_cache_addr_, cache_ptr, sizeof(kmem_cache_t))) return 0;
	EnterCriticalSection(&cache_ptr->critical_section);
	uint8_t code = cache_ptr->error;
	LeaveCriticalSection(&cache_ptr->critical_section);
	return code;
}

void* kmem_cache_alloc_obj(kmem_cache_t* cache_ptr, kmem_slab_t* slab_ptr) {
	void* addr = slab_ptr->free;
	slab_ptr->free = *((void**)slab_ptr->free);
	slab_ptr->taken_count++;

	if (cache_ptr->ctor) cache_ptr->ctor(addr); // pozivanje konstruktora za alocirati objekat

	if (cache_ptr->slabs_half_full == slab_ptr) { // bio slab_ptr polupun
		if (!slab_ptr->free) { // ako je slab_ptr sada pun
			cache_ptr->slabs_half_full = slab_ptr->next;
			slab_ptr->next = cache_ptr->slabs_full;
			cache_ptr->slabs_full = slab_ptr;
		}
	}
	else { // slab_ptr bio prazan, sada polupun
		cache_ptr->slabs_empty = slab_ptr->next;
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
	InitializeCriticalSectionAndSpinCount(&cache_ptr->critical_section, 0x00000400);

	// racunanje velicine slab-a i broja slotova po slab-u:
	// TODO korigovati algoritam....
	uint16_t blocks_per_slab = 1;
	uint32_t slots_per_slab = (blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t)) / data_size;
	while (slots_per_slab < MIN_SLOTS_PER_SLAB) {
		blocks_per_slab++;
		slots_per_slab = (blocks_per_slab * BLOCK_SIZE - sizeof(kmem_slab_t)) / data_size;
	}
	cache_ptr->blocks_per_slab = blocks_per_slab;
	cache_ptr->slots_per_slab = slots_per_slab;
}

void kmem_slab_init(kmem_slab_t* slab_ptr, kmem_cache_t* cache_ptr) {
	// inicijalizacija polja slab-a
	slab_ptr->slot_size = cache_ptr->data_size;
	slab_ptr->slot_count = cache_ptr->slots_per_slab;
	slab_ptr->taken_count = 0;

	// inicijalizacija liste free
	slab_ptr->free = slab_ptr + 1;
	printf("velicina jednog slab-a: %d\n", sizeof(kmem_slab_t));
	for (uint32_t i = 0; i < slab_ptr->slot_count - 1; i++) {
		*(void**)((uint8_t*)slab_ptr->free + i * slab_ptr->slot_size) = (uint8_t*)slab_ptr->free + (i + 1) * slab_ptr->slot_size;
	}
	*(void**)((uint8_t*)slab_ptr->free + (slab_ptr->slot_count - 1) * slab_ptr->slot_size) = NULL;

	// azuriranje listi
	slab_ptr->next = cache_ptr->slabs_empty;
	cache_ptr->slabs_empty = slab_ptr;
	cache_ptr->slab_count++;
}

void* kmem_slab_alloc(kmem_cache_t* cache_ptr) {
	kmem_slab_t* slab_ptr = kmem_buddy_alloc_mem(cache_ptr->blocks_per_slab);
	if (!slab_ptr) { // nemoguce alocirati novi slab
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
	return kmem_buddy_free_mem(slab_ptr, cache_ptr->blocks_per_slab);
}

void* search_cache_by_name(const uint8_t* name) {
	if (!name) return NULL;
	kmem_cache_t* master_cache = master_cache_addr_;
	kmem_slab_t* slab_ptr = master_cache->slabs_half_full;
	while (slab_ptr) {
		uint8_t* slot_ptr = slab_ptr + 1;
		for (uint16_t i = 0; i < slab_ptr->slot_count; i++)
			if (strcmp(((kmem_cache_t*)(slot_ptr + i * master_cache->data_size))->name, name) == 0) return slot_ptr + i * master_cache->data_size;
		slab_ptr = slab_ptr->next;
	}
	slab_ptr = master_cache->slabs_full;
	while (slab_ptr) {
		uint8_t* slot_ptr = slab_ptr + 1;
		for (uint16_t i = 0; i < slab_ptr->slot_count; i++)
			if (strcmp(((kmem_cache_t*)(slot_ptr + i * master_cache->data_size))->name, name) == 0) return slot_ptr + i * master_cache->data_size;
		slab_ptr = slab_ptr->next;
	}

	return NULL;
}

uint8_t object_in_cache(kmem_cache_t* cache_ptr, void* object_ptr, size_t size) {
	if (!cache_ptr || !object_ptr) return 0;
	if (cache_ptr->data_size != size) return 0;

	kmem_slab_t* slab_ptr = cache_ptr->slabs_half_full;
	while (slab_ptr) {
		if (object_in_slab(slab_ptr, object_ptr, size)) return 1;
		slab_ptr = slab_ptr->next;
	}

	slab_ptr = cache_ptr->slabs_full;
	while (slab_ptr) {
		if (object_in_slab(slab_ptr, object_ptr, size)) return 1;
		slab_ptr = slab_ptr->next;
	}

	return 0;
}

uint8_t object_in_slab(kmem_slab_t* slab_ptr, void* object_ptr, size_t size) { // ne proverava se da li je zauzet doduse... mozda bi trebalo...
	if (!slab_ptr || !object_ptr) return 0;
	if (slab_ptr->slot_size != size) return 0;
	if (!(object_ptr > slab_ptr && object_ptr < (uint8_t*)slab_ptr + sizeof(kmem_slab_t) + slab_ptr->slot_size * slab_ptr->slot_count)) return 0;
	if (((uint8_t*)object_ptr - ((uint8_t*)slab_ptr + sizeof(kmem_slab_t))) % size == 0) return 1;
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

uint8_t exponent_of_two(size_t size) {
	if (size < 1) return -1;

	uint8_t valid = 0;
	uint16_t exponent = 0;
	for (exponent; (1 << exponent) <= size ; exponent++)
		if (size == (1 << exponent)) return exponent;

	return -1;
}