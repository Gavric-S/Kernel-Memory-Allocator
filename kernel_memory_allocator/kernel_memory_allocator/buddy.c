#include "buddy.h"
#include "slab.h"

void kmem_init_impl(void *space, uint32_t block_num) {
	if (space < 0 || block_num <= 0) return;
	space_ = space;
	block_num_ = block_num;

	// racunanje duzine liste pokazivaca na slobodne delove memorije buddy sistema...
	uint16_t free_buddy_length = 0;
	uint16_t leftover_space_blocks;
	while ((1 << free_buddy_length) < block_num) free_buddy_length++;

	// racunanje offset-a od pocetka dodeljene memorije space na kom ce se nalaziti gorepomenuta lista...
	// TODO: mozda ovde uracunati i jos neke strukture pored buddy pokazivaca...
	uint32_t offset_bytes = free_buddy_length * sizeof(buddy_free_t);

	printf("velicina jednog cache-a: %d\n", sizeof(kmem_cache_t));
	offset_bytes += /*2 * */sizeof(kmem_cache_t); // TODO ako menjas ovde moras i u inline funkcijama
	// TODO: inicijalizacija dva cache objekta:
	kmem_cache_init((uint8_t*)space_ + offset_bytes, "CACHES", sizeof(kmem_cache_t), NULL, NULL);
	// kmem_cache_init((uint8_t*)space_ + offset_bytes + sizeof(kmem_cache_t), "BUFFER_CACHES", sizeof(kmem_cache_t), NULL, NULL);

	uint32_t offset_blocks = offset_bytes / BLOCK_SIZE + (offset_bytes % BLOCK_SIZE) ? 1 : 0;;
	block_num -= offset_blocks;
	if ((1 << free_buddy_length) > block_num) free_buddy_length--;
	// exp_ = free_buddy_length;
	leftover_space_blocks = block_num - (1 << free_buddy_length);

	// avail_space_ = (uint8_t*)space + offset_blocks * BLOCK_SIZE;

	// inicijalizacija liste pokazivaca na slobodne delove memorije buddy sistema...
	for (uint32_t i = 0; i < free_buddy_length; i++) ((buddy_free_t*)space_ + i)->free = NULL;
	((buddy_free_t*)space_ + free_buddy_length)->free = ((buddy_free_t*)avail_space_());
	((buddy_free_t*)avail_space_())->free = NULL;
	// azuriranje liste pokazivaca memorijom koja je iza memorije obuhvacene najvecim stepenom dvojke...
	void* leftover_space_pointer = (uint8_t*)avail_space_() + (1 << free_buddy_length) * BLOCK_SIZE;
	while (leftover_space_blocks > 0) {
		uint16_t exponent = 0;
		while ((1 << exponent) < leftover_space_blocks) exponent++;
		if ((1 << exponent) > leftover_space_blocks) exponent--;
		leftover_space_blocks -= (1 << exponent);
		((buddy_free_t*)leftover_space_pointer)->free = ((buddy_free_t*)space_ + exponent)->free;
		((buddy_free_t*)space_ + exponent)->free = leftover_space_pointer;
		leftover_space_pointer = (uint8_t*)leftover_space_pointer + (1 << exponent) * BLOCK_SIZE;
	}

	//for (uint32_t i = 0; i <= free_buddy_length; i++) {
	//	buddy_free_t* curr = ((buddy_free_t*)space_ + i)->free;
	//	while (curr != NULL) {
	//		printf("%p\t", curr);
	//		curr = curr->free;
	//	}
	//	if (curr == NULL) printf("NULL!\n");
	//}
	printf("\n");
	print_buddy_ptr_list();
	printf("\n");

	// markiranje pozicije prvog kesa kao prazne (pod pretpostavkom da ima mesta u prvom bloku za bar taj jedan cache):
	// treba korigovati!
	//((kmem_cache_t*)((buddy_free_t*)space + free_buddy_length))->name = NULL; // glava cache liste objekata
	//(((kmem_cache_t*)((buddy_free_t*)space + free_buddy_length)) + 1)->name = NULL; // glava cache liste bafera
}

uint32_t exp_() {
	uint16_t max_buddy_exp = 0;
	while ((1 << max_buddy_exp) < block_num_) max_buddy_exp++;
	uint32_t offset_blocks = (max_buddy_exp * sizeof(buddy_free_t) + /*2 * */sizeof(kmem_cache_t)) / BLOCK_SIZE + 1;
	if ((1 << max_buddy_exp) > block_num_ - offset_blocks) max_buddy_exp--;
	return max_buddy_exp;
}

inline void* avail_space_() {
	uint16_t max_buddy_exp = 0;
	while ((1 << max_buddy_exp) < block_num_) max_buddy_exp++;
	uint32_t offset_blocks = (max_buddy_exp * sizeof(buddy_free_t) + /*2 * */sizeof(kmem_cache_t)) / BLOCK_SIZE + 1;
	return (uint8_t*)space_ + offset_blocks * BLOCK_SIZE;
}

void kmem_cache_init(void* addr, uint16_t* name, size_t data_size, void(*ctor)(void*), void(*dctor)(void*)) { // TODO provera treba da se radi u funkcijama pozivaocima?
	kmem_cache_t* cache_addr = addr;
	for (uint32_t i = 0; i < strlen(name); i++) cache_addr->name[i] = name[i];
	cache_addr->name[strlen(name)] = '\0';
	cache_addr->data_size = data_size;
	cache_addr->slabs_empty = NULL;
	cache_addr->slabs_half_full = NULL;
	cache_addr->slabs_full = NULL;
	cache_addr->ctor = ctor;
	cache_addr->dctor = dctor;
	// TODO...
	// slab_size... (koliko blokova)
}

kmem_cache_t* kmem_cache_create_impl(const uint8_t*name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	//if (!name || size < 1) return NULL;
	//kmem_cache_t* cache_head = _get_object_cache_head_;
	//uint32_t valid_code = is_cache_valid(NULL);

	//if (valid_code & NO_OBJECT_CACHE_HEAD) {
	//	// kmem_cache_init(cache_head, name, size, ctor, dctor); 
	//	printf("nema\n");
	//} 
	//else {
	//	printf("ima\n");
	//	kmem_cache_t* cache_prev = NULL;
	//	while (cache_head != NULL) {
	//		cache_prev = cache_head;
	//		cache_head = cache_head->next_cache;
	//	}
	//	// provera da li ima mesta u ovom bloku za novi kes...
	//	uint8_t* block_prev = _get_block_(cache_prev);
	//	cache_prev++;
	//	if (_get_block_(cache_prev) != block_prev || _get_block_(cache_prev + 1) != block_prev) cache_prev = kmem_buddy_alloc_mem(1); // nema..
	//	// kmem_cache_init(cache_prev, name, size, ctor, dctor);
	//}
	// TODO: izracunati velicinu neiskoriscenog prostora

	kmem_cache_t* master_cache_ptr = master_cache_;
	void* new_cache_ptr = kmem_cache_alloc_impl(master_cache_ptr);
	kmem_cache_init(new_cache_ptr, name, size, ctor, dctor);
	return new_cache_ptr;
	// TODO: obraditi izuzetne slucajeve...
}

void* kmem_cache_alloc_impl(kmem_cache_t* cache_ptr) {
	//uint32_t valid_code = is_cache_valid(cache_ptr);
	//if (!(valid_code & VALID_OBJECT_CACHE)) return NULL;
	// TODO: provera validnosti adrese cache-a...

	void* object_ptr = NULL;
	if (cache_ptr->slabs_half_full) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_half_full, cache_ptr->ctor); // postoji polupopunjen slab
	else if (cache_ptr->slabs_empty) object_ptr = kmem_cache_alloc_obj(cache_ptr, cache_ptr->slabs_half_full, cache_ptr->ctor); // postoji prazan slab
	else { // potrebno alocirati novi slab
		kmem_slab_t* new_slab = kmem_buddy_alloc_mem(cache_ptr->slab_size / BLOCK_SIZE + (cache_ptr->slab_size % BLOCK_SIZE) ? 1 : 0);
		if (!new_slab) return NULL;  // nemoguce alocirati novi slab
		kmem_slab_init(new_slab, cache_ptr);
		object_ptr = kmem_cache_alloc_obj(cache_ptr, new_slab, cache_ptr->ctor);
	}
	return object_ptr;
}
 
uint16_t max_exp(uint32_t block_num) {
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;
	if ((1 << exponent) > block_num) exponent--;
	return exponent;
}

void kmem_init_cache(kmem_cache_t* cache, const uint8_t*name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	// cache->name = name;
	cache->data_size = size;
	cache->ctor = ctor;
	cache->dctor = dctor;
	cache->slabs_empty = NULL;
	cache->slabs_full = NULL;
	cache->slabs_half_full = NULL;
	cache->expanded = 0;
	cache->blk_count = 0; //.
	cache->slab_count = 0;
	cache->slab_size = BLOCK_SIZE; 
	cache->slot_count = (BLOCK_SIZE - sizeof(kmem_slab_t)) / size;
	cache->perc_full = 0; //.
	cache->next_cache = NULL;
	cache->prev_cache = NULL;
}

void* kmem_buddy_alloc_mem(uint32_t block_num) {
	if (block_num < 1) return NULL;

	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	uint16_t i = 0;
	if (!found_free_space(exponent, &i)) return NULL;

	void* ret = direct_alloc(i, block_num);
	if (ret) {
		print_buddy_ptr_list();
		return ret;
	}
	else ret = disjoin_alloc(i, block_num);

	printf("adresa: %p\n", ret);
	print_buddy_ptr_list();
	return ret;
}

uint8_t found_free_space(uint16_t exponent, uint16_t*i) {
	for (; *i <= exp_(); (*i)++)
		if (((buddy_free_t*)space_ + *i)->free != NULL && *i >= exponent) return 1;
	return 0;
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
	if (!lower) {} // TODO ali ni ne treba mi ovo jer su sve ostale provere vec odradjene
	else ((buddy_free_t*)space_ + i)->free = lower->free;
	return lower;
}

uint32_t kmem_buddy_dealloc_mem(void* target, uint32_t block_num) { // vraca broj oslobodjenih blokova
	// dodaj adresu mete u listu
	uint16_t exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	// invalidan chunk
	if (!chunk_buddy_is_valid(target, exponent)) return 0;
	// vec slobodan
	if (in_list(target, exponent)) return 0;

	// dohvati parnjaka:
	void* buddy = get_buddy(target, exponent);
	if (!buddy) { // ukoliko nema parnjaka samo oslobodi chunk na datoj adresi
		attach_to_list(((buddy_free_t*)space_ + exponent), target);
	}

	// spajaj slobodne parnjake dok god mozes
	while (buddy && in_list(buddy, exponent)) {
		detach_from_list(buddy, exponent);
		if (in_list(target, exponent)) detach_from_list(target, exponent);
		if (target > buddy) target = buddy;
		attach_to_list(((buddy_free_t*)space_ + exponent + 1), target);
		buddy = get_buddy(target, exponent + 1);
		exponent++;
	}

	return block_num;
}

uint8_t chunk_buddy_is_valid(void* addr, uint32_t exp) {
	// da li je adresa uopste u okviru memorije
	if (!chunk_is_in_bounds(addr, exp)) return 0;

	// da li je udaljen ceo broj blokova stepenovanih eksponentom od pocetka memorije
	uint32_t offset_blocks = addr_offset_bytes(addr) / BLOCK_SIZE;
	if (offset_blocks % (1 << exp) != 0) return 0;

	return 1;
}

void* get_buddy(void* addr, uint32_t exp) { // TODO: moguce da nema parnjaka - pokriti...
	if (exp > exp_()) return NULL;

	uint32_t offset_blocks = addr_offset_bytes(addr) / BLOCK_SIZE;

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

uint32_t addr_offset_bytes(void* addr) {
	uint8_t* relative_mem_start = avail_space_();
	uint8_t* overflow_mem_start = (uint8_t*)avail_space_() + ((1 << exp_()) * BLOCK_SIZE); /* TODO ovo mozda bude problematicno */
	if ((uint8_t*)addr > overflow_mem_start) relative_mem_start = overflow_mem_start;

	return (uint8_t*)addr - (uint8_t*)relative_mem_start;
}

uint8_t chunk_is_in_bounds(void* addr, uint32_t exp) {
	if (addr < space_) return 1;
	if ((uint8_t*)addr + (1 << exp) * BLOCK_SIZE <= (uint8_t*)space_ + block_num_ * BLOCK_SIZE) return 1;
	return 0;
}

uint8_t in_list(buddy_free_t *buddy, uint32_t exponent) { // TODO
	buddy_free_t* curr = ((buddy_free_t*)space_ + exponent)->free;
	while (curr) { 
		if (curr == buddy) return 1; 
		curr = curr->free;
	}
	return 0;
}

void detach_from_list(buddy_free_t *target, uint8_t exponent) {
	buddy_free_t* head = ((buddy_free_t*)space_ + exponent);
	if (head->free == target) {
		head->free = target->free;
		target->free = NULL;
		return;
	}
	buddy_free_t *prev = head->free, *curr = prev->free;
	while (curr) {
		if (curr == target) {
			prev->free = target->free;
			target->free = NULL;
		}
		prev = curr;
		curr = curr->free;
	}
}

void attach_to_list(buddy_free_t *head, buddy_free_t *target) {
	target->free = head->free;
	head->free = target;
}
 
uint32_t is_cache_valid(kmem_cache_t* cache) {
	uint32_t ret = 0;
	kmem_cache_t* current = master_cache_;
	if (current->name == NULL) { 
		ret |= NO_OBJECT_CACHE_HEAD; 
		current = NULL;
	}
	while (current) {
		if (current == cache) {
			ret |= VALID_OBJECT_CACHE;
			break;
		}
		current = current->next_cache;
	}
	current = master_cache_;
	if (current->name == NULL) {
		ret |= NO_BUFFER_CACHE_HEAD;
		current = NULL;
	}
	while ((ret & VALID_OBJECT_CACHE == 0) && current) {
		if (current == cache) {
			ret |= VALID_BUFFER_CACHE;
			break;
		}
		current = current->next_cache;
	}
	return ret;
}

//void* kmem_allocate_slab(size_t size) {
//	if (size < 1) return NULL;
//	uint32_t blocks = size / BLOCK_SIZE + (size % BLOCK_SIZE) ? 1 : 0;
//	return kmem_buddy_alloc_mem(blocks);
//}

uint32_t kmem_deallocate_slab(kmem_slab_t* target) {
	uint32_t block_num = (target->slot_count * target->slot_size + sizeof(kmem_slab_t)) / BLOCK_SIZE; // ovo bi trebalo da bude deljivo (ako nije greska!) TODO proveriti
	return kmem_buddy_dealloc_mem(target, block_num);
}


void* kmem_cache_alloc_obj(kmem_cache_t* cache, kmem_slab_t* slab, void(*ctor)(void *)) {
	void* addr = slab->free;
	slab->free = *((void**)slab->free); // TODO: sta se ovde zapravo zbiva..
	slab->taken_count++;
	if (ctor) ctor(addr);
	if (cache->slabs_half_full == slab) { // bio slab polupun
		if (!slab->free) { // ako je slab sada pun
			cache->slabs_half_full = slab->next;
			slab->next = cache->slabs_full;
			cache->slabs_full = slab;
		}
	}
	else { // slab bio prazan, sada polupun
		cache->slabs_empty = slab->next;
		slab->next = cache->slabs_half_full;
		cache->slabs_half_full = slab;
	}
	return addr;
}

void kmem_cache_free_impl(kmem_cache_t *cache_ptr, void *object_ptr) {
	//uint32_t valid_code = is_cache_valid(cache_ptr);
	//if (valid_code & VALID_OBJECT_CACHE) return;
	// TODO: provera validnosti adrese cache-a...

	// nadji slab u kom se nalazi
	uint8_t* slot_ptr = NULL;
	uint8_t found = 0;
	// full obilazak
	kmem_slab_t* current_full = cache_ptr->slabs_full;
	while (current_full) {
		slot_ptr = ((uint8_t*)(current_full + 1));
		for (uint32_t i = 0; i < current_full->slot_count; i++) {
			if (slot_ptr + current_full->slot_size * i == object_ptr) {
				found = 1;
				break;
			}
		}
		if (found) break;
		current_full = current_full->next;
	}
	// half-full obilazak
	kmem_slab_t* current_half_full = NULL;
	if (found == 0) {
		current_half_full = cache_ptr->slabs_half_full;
		while (current_half_full) {
			slot_ptr = ((uint8_t*)(current_half_full + 1));
			for (uint32_t i = 0; i < current_half_full->slot_count; i++) {
				if (slot_ptr + current_half_full->slot_size * i == object_ptr) {
					found = 2;
					break;
				}
			}
			if (found) break;
			current_half_full = current_half_full->next;
		}
	}
	if (found == 1) { // u punom slab-u
		((kmem_slab_t*)slot_ptr)->free /*slot_ptr*/ = *((void**)current_full->free); // TODO: ovo nije dobro sigurno jer nista ne upisujem u memoriju...
		// ali sta ako je je sam objekat ovde manji od 4 bajta? onda necu moci da stavljam free pokazivac u sam slot???
		current_full->free = ((void*)slot_ptr); //
		current_full->taken_count--;
		// prebacivanje u polupune
		cache_ptr->slabs_full = current_full->next;
		current_full->next = cache_ptr->slabs_half_full;
		cache_ptr->slabs_half_full = current_full;
	}
	else if (found == 2) { // u polupunom slab-u
		((kmem_slab_t*)slot_ptr)->free = *((void**)current_half_full->free); // TODO proveriti obavezno // TODO ovde namestio sada
		current_half_full->free = ((void*)slot_ptr); //
		current_half_full->taken_count--;
		// prebacivanje u empty
		if (current_half_full->taken_count == 0) {
			cache_ptr->slabs_half_full = current_half_full->next;
			current_half_full->next = cache_ptr->slabs_empty;
			cache_ptr->slabs_empty = current_half_full;
		}
	}
	// ukoliko nisi nasao slab samo se vrati
	return;
}

void* kmalloc_impl(size_t size) {
	uint32_t exp = max_exp(size);
	if ((1 << exp) != size) return NULL; // ???
	if (exp < 5 || exp > 17) return NULL;
	char* name = generate_buffer_name(size, exp);
	// printf("%s", name);
	// alociranje kesa
	kmem_cache_t* buffer_cache = search_by_cache_name(master_cache_, name);
	if (!buffer_cache) { // vec postoji odgovarajuci cache
		buffer_cache = kmem_cache_create_impl(name, size, NULL, NULL);
		if (!buffer_cache) return NULL;
	}
	return kmem_cache_alloc_impl(buffer_cache);
	//uint32_t valid_code = is_cache_valid(cache_curr);
	//if (valid_code & NO_BUFFER_CACHE_HEAD) {
	//	// kreiraj novi kes na mestu cache_head-a...
	//	// napravi mu jedan slab u koji ces staviti ovaj buffer...

	//}
	//else if (!(valid_code & VALID_BUFFER_CACHE)) {
	//	// kreiraj novi kes...
	//	// napravi mu jedan slab u koji ces staviti ovaj buffer...
	//}
	//else {
	//	// stavi bafer u cache...
	//}
}

void kfree_impl(const void* objp) {
	kmem_cache_t* cache_curr = master_cache_;
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

void* search_by_cache_name(kmem_cache_t* cache, char* name) {
	return NULL; // TODO: implementirati
}

void kmem_slab_init(kmem_slab_t* slab_ptr, kmem_cache_t* cache_ptr) {
	// inicijalizacija polja slab-a
	slab_ptr->slot_size = cache_ptr->data_size;
	slab_ptr->slot_count = cache_ptr->slot_count;
	slab_ptr->taken_count = 0;
	
	// TODO TESTIRAJ!
	// inicijalizacija liste free
	slab_ptr->free = (void*)(slab_ptr + 1);
	for (uint32_t i = 0; i < slab_ptr->slot_count - 1; i++)
		*(void**)((uint8_t*)slab_ptr->free + i * slab_ptr->slot_size) = (uint8_t*)slab_ptr->free + (i + 1) * slab_ptr->slot_size;
	*(void**)((uint8_t*)slab_ptr->free + (slab_ptr->slot_count /*- 1*/) * slab_ptr->slot_size) = NULL;

	// azuriranje lista
	slab_ptr->next = cache_ptr->slabs_empty;
	cache_ptr->slabs_empty = slab_ptr;
	cache_ptr->slab_count++;
}

const uint8_t* generate_buffer_name(size_t size, uint32_t N) {
	uint8_t num[3];
	uint8_t name[8] = "name-";
	sprintf(num, "%d", N);
	if (N > 9) num[2] = '\0';
	else num[1] = '\0';
	strcat(name, num);
	if (N > 9) name[7] = '\0';
	else name[6] = '\0';
	return name;
}


void print_buddy_ptr_list() {
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