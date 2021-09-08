#include "buddy.h"
#include "slab.h"

void kmem_init_buddy(void *space, int block_num) {
	if (space < 0 || block_num <= 0) return;
	space_ = space;
	block_num_ = block_num;

	// racunanje duzine liste pokazivaca na slobodne delove memorije buddy sistema...
	unsigned short free_buddy_length = 0;
	unsigned short leftover_space_blocks;
	while ((1 << free_buddy_length) < block_num) free_buddy_length++;

	// racunanje offset-a od pocetka dodeljene memorije space na kom ce se nalaziti gorepomenuta lista...
	// TODO: mozda ovde uracunati i jos neke strukture pored buddy pokazivaca...
	unsigned int offset_bytes = free_buddy_length * sizeof(buddy_free_t);
	unsigned int offset_blocks = offset_bytes / BLOCK_SIZE + 1;
	block_num -= offset_blocks;
	if ((1 << free_buddy_length) > block_num) free_buddy_length--;
	exp_ = free_buddy_length;
	leftover_space_blocks = block_num - (1 << free_buddy_length);

	avail_space_ = (char*)space + offset_blocks * BLOCK_SIZE;

	// inicijalizacija liste pokazivaca na slobodne delove memorije buddy sistema...
	for (int i = 0; i < free_buddy_length; i++) ((buddy_free_t*)space_ + i)->free = NULL;
	((buddy_free_t*)space_ + free_buddy_length)->free = ((buddy_free_t*)avail_space_);
	((buddy_free_t*)avail_space_)->free = NULL;
	// azuriranje liste pokazivaca memorijom koja je iza memorije obuhvacene najvecim stepenom dvojke...
	void* leftover_space_pointer = (char*)avail_space_ + (1 << free_buddy_length) * BLOCK_SIZE;
	while (leftover_space_blocks > 0) {
		unsigned short exponent = 0;
		while ((1 << exponent) < leftover_space_blocks) exponent++;
		if ((1 << exponent) > leftover_space_blocks) exponent--;
		leftover_space_blocks -= (1 << exponent);
		((buddy_free_t*)leftover_space_pointer)->free = ((buddy_free_t*)space_ + exponent)->free;
		((buddy_free_t*)space_ + exponent)->free = leftover_space_pointer;
		leftover_space_pointer = (char*)leftover_space_pointer + (1 << exponent) * BLOCK_SIZE;
	}

	//for (int i = 0; i <= free_buddy_length; i++) {
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

kmem_cache_t* kmem_cache_create_buddy(const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	if (!name || size < 1) return NULL;
	kmem_cache_t* cache_head = _get_object_cache_head_;
	int valid_code = is_cache_valid(NULL);
	printf("%d", sizeof(kmem_cache_t));
	if (valid_code & NO_OBJECT_CACHE_HEAD) {
		// init_cache(cache_head, name, size, ctor, dctor); 
		printf("nema\n");
	} 
	else {
		printf("ima\n");
		kmem_cache_t* cache_prev = NULL;
		while (cache_head != NULL) {
			cache_prev = cache_head;
			cache_head = cache_head->next_cache;
		}
		// provera da li ima mesta u ovom bloku za novi kes...
		char* block_prev = _get_block_(cache_prev);
		cache_prev++;
		if (_get_block_(cache_prev) != block_prev || _get_block_(cache_prev + 1) != block_prev) cache_prev = kmem_buddy_alloc_mem(1); // nema..
		// init_cache(cache_prev, name, size, ctor, dctor);
	}
	// TODO: izracunati velicinu neiskoriscenog prostora
}
 
unsigned short maxExponent(int block_num) {
	unsigned short exponent = 0;
	while ((1 << exponent) < block_num) exponent++;
	if ((1 << exponent) > block_num) exponent--;
	return exponent;
}

void kmem_init_cache(kmem_cache_t* cache, const char *name, size_t size, void(*ctor)(void *), void(*dctor)(void *)) {
	cache->name = name;
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

void* kmem_buddy_alloc_mem(int block_num) {
	if (block_num < 1) return NULL;

	unsigned short exponent = 0;
	while ((1 << exponent) < block_num) exponent++;

	short i = 0;
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

char found_free_space(unsigned short exponent, short *i) {
	for (; *i <= exp_; (*i)++)
		if (((buddy_free_t*)space_ + *i)->free != NULL && *i >= exponent) return 1;
	return 0;
}

void* direct_alloc(char i, int block_num) {
	if ((1 << i) == block_num || ((1 << i) < (block_num << 1))) {
		void* ret = ((buddy_free_t*)space_ + i)->free;
		((buddy_free_t*)space_ + i)->free = (((buddy_free_t*)space_ + i)->free)->free;
		return ret;
	}
	return NULL;
}

void* disjoin_alloc(char i, int block_num) {
	buddy_free_t* lower = NULL;
	while ((1 << i) > block_num) {
		lower = ((buddy_free_t*)space_ + i)->free;
		buddy_free_t* higher = (((char*)(((buddy_free_t*)space_ + i)->free)) + (1 << i - 1) * BLOCK_SIZE);
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
	((buddy_free_t*)space_ + i)->free = lower->free;
	return lower;
}

int kmem_buddy_dealloc_mem(void* target, int block_num) { // vraca broj oslobodjenih blokova
	// dodaj adresu mete u listu
	unsigned short exponent = 0;
	while ((1 << exponent) < block_num) exponent++;
	// mozda ovo odloziti dok se ne vidi da li je tu parnjak...
	//((buddy_free_t*)target)->free = ((buddy_free_t*)space_ + exponent)->free;
	//((buddy_free_t*)space_ + exp_)->free = target;

	// dohvati parnjaka:
	void* buddy = get_buddy(target, exponent);
	if (!buddy) {
		attach_to_list(((buddy_free_t*)space_ + exponent), target);
	}
	while (buddy && in_list(buddy, exponent)) {
		detach_from_list(buddy, exponent);
		// buddy_free_t *curr = ((buddy_free_t*)space_ + exponent)->free, *prev = NULL;
		if (target > buddy) target = buddy;
		attach_to_list(((buddy_free_t*)space_ + exponent + 1), target);
		buddy = get_buddy(target, exponent + 1);
	}

	return block_num;

	//while (buddy) {
	//	// pogledaj da li se u listi nalazi parnjak
	//	int found = 0;
	//	// da li uopste moze ovako da se iterira kroz listu TODO TESTIRAJ
	//	buddy_free_t* current_free = ((buddy_free_t*)space_ + exp_)->free;
	//	buddy_free_t* previous_free = NULL;
	//	while (current_free) {
	//		if (current_free == buddy) {
	//			found = 1;
	//			break;
	//		}
	//		previous_free = current_free;
	//		current_free = current_free->free;
	//	}
	//	if (found) { // oba su sada slobodna -> spoj ih (ovo sve treba u ciklusu)
	//		void* first = target > buddy ? buddy : target;
	//		void* second = target > buddy ? target : buddy;
	//		// prevezi pokazivace u exp listi...
	//		((buddy_free_t*)space_ + exp_)->free = ((buddy_free_t*)target)->free;
	//		previous_free->free = current_free->free;
	//		// prevezi pokazivace u exp + 1 listi...
	//		// nije moguce da smo na posledjem nivou tako da exp + 1 jeste validno svakako
	//		((buddy_free_t*)first)->free = ((buddy_free_t*)space_ + exp_ + 1)->free;
	//		((buddy_free_t*)space_ + exp_ + 1)->free = first;
	//		exp_++;
	//		target = first;
	//		buddy = get_buddy(target, exp_);
	//	}
	//	else break; // ovo ne bi smelo nikada da se desi!
	//}
}


void* get_buddy(void* addr, int exp) { // TODO: moguce da nema parnjaka - pokriti...
	if (exp > exp_) return NULL;

	char* relative_mem_start = avail_space_;
	char* overflow_mem_start = (char*)avail_space_ + ((1 << exp_) * BLOCK_SIZE);
	if ((char*)addr > overflow_mem_start) relative_mem_start = overflow_mem_start;

	int offset_bytes = (char*)addr - (char*)avail_space_;
	int offset_blocks = offset_bytes / BLOCK_SIZE;
	long pwr = 1 << exp;

	void* ret = NULL;
	if (offset_blocks % 2 == 0) { // ja sam donji parnjak
		void* buddy = (char*)addr + (1 << exp) * BLOCK_SIZE;
		if (is_valid_addr(buddy, exp)) ret = buddy;
	}
	else {
		void* buddy = (char*)addr - (1 << exp) * BLOCK_SIZE;
		if (is_valid_addr(buddy, exp)) ret = buddy;
	}
	return ret;
}

char is_valid_addr(void* addr, int exp) {
	if ((char*)addr + (1 << exp) * BLOCK_SIZE < (char*)space_ + block_num_ * BLOCK_SIZE) return 1;
	return 0;
}

char in_list(buddy_free_t *buddy, int exponent) { // TODO
	buddy_free_t* curr = ((buddy_free_t*)space_ + exponent)->free;
	while (curr) if (curr == buddy) return 1;
	return 0;
}

void detach_from_list(buddy_free_t *target, char exponent) {
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
 
int is_cache_valid(kmem_cache_t* cache) {
	int ret = 0;
	kmem_cache_t* current = _get_object_cache_head_;
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
	current = _get_buffer_cache_head_;
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

void* kmem_allocate_slab(size_t size) {
	if (size < 1) return NULL;
	int blocks = size / BLOCK_SIZE + (size % BLOCK_SIZE) ? 1 : 0;
	return kmem_buddy_alloc_mem(blocks);
}

int kmem_deallocate_slab(kmem_slab_t* target) {
	int block_num = (target->slot_count * target->slot_size + sizeof(kmem_slab_t)) / BLOCK_SIZE; // ovo bi trebalo da bude deljivo (ako nije greska!) TODO proveriti
	return kmem_buddy_dealloc_mem(target, block_num);
}

void* kmem_cache_alloc_obj(kmem_cache_t* cache, kmem_slab_t* slab, void(*ctor)(void *)) {
	// provera nije potrebna jer je izvrsena ranije
	void* addr = slab->free;
	slab->free = *((void**)slab->free); // TODO proveriti obavezno
	slab->taken_count++;
	if (ctor) ctor(addr);
	if (cache->slabs_half_full == slab) { // bio slab polupun
		if (!slab->free) { // ako je slab sada pun
			cache->slabs_half_full = slab->next;
			slab->next = cache->slabs_full;
			cache->slabs_full = slab;
		}
	}
	else { // slab bio prazan
		// slab sada polupun
		cache->slabs_empty = slab->next;
		slab->next = cache->slabs_half_full;
		cache->slabs_half_full = slab;
	}
	return addr;
}

void kmem_init_slab(kmem_slab_t* slabp, kmem_cache_t* cachep) {
	slabp->slot_size = cachep->data_size;
	slabp->slot_count = cachep->slot_count;
	slabp->taken_count = 0;
	// inicijalizacija liste free..
	// TODO TESTIRAJ!
	slabp->free = (void*)(slabp + 1);
	for (int i = 0; i < slabp->slot_count - 1; i++) 
		*(void**)((char*)slabp->free + i * slabp->slot_size) = (char*)slabp->free + (i + 1) * slabp->slot_size;
	*(void**)((char*)slabp->free + (slabp->slot_count - 1) * slabp->slot_size) = NULL;
	// moze ovde jer se uvek pravi prazan slab vezan za cache na koji pokazuje cachep
	slabp->next = cachep->slabs_empty;
	cachep->slabs_empty = slabp;
	cachep->slab_count++;
}

const char* generate_buffer_name(size_t size, int N) {
	char num[3];
	char name[8] = "name-";
	sprintf(num, "%d", N);
	if (N > 9) num[2] = '\0';
	else num[1] = '\0';
	strcat(name, num);
	if (N > 9) name[7] = '\0';
	else name[6] = '\0';
	return name;
}


void print_buddy_ptr_list() {
	for (int i = 0; i <= exp_; i++) {
		buddy_free_t* curr = ((buddy_free_t*)space_ + i)->free;
		printf("%d: ", i);
		while (curr != NULL) {
			printf("%p\t", curr);
			curr = curr->free;
		}
		if (curr == NULL) printf("NULL!\n");
	}
}