#include "sysemu/espt_int.h"

#define PAGE_SIZE qemu_real_host_page_size
#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))

ESPTState espt_state;

static void espt_entry_list_init(void)
{
	struct ESPTFlushEntryVec * entry = &espt_state.espt_entry;
	
	entry->addr_list = (target_ulong *)g_malloc0_n(16, sizeof(target_ulong));
	entry->capacity = 16;
	entry->size = 0;
}

void espt_entry_list_insert(target_ulong elem)
{
	struct ESPTFlushEntryVec * entry = &espt_state.espt_entry;
	
	if(entry->size == entry->capacity){
		int new_capacity = entry->capacity * 2;
		target_ulong * tmp = (target_ulong *)g_malloc0_n(new_capacity, sizeof(target_ulong));
		
		memcpy(tmp, entry->addr_list, entry->size * sizeof(target_ulong));
		g_free(entry->addr_list);
		entry->addr_list = tmp;
		
		entry->addr_list[entry->size++] = elem;
		entry->capacity = new_capacity;
		return;
	}
	entry->addr_list[entry->size++] = elem;
}

int espt_entry_flush_all(void)
{	struct ESPTEntry espt_entry;
	struct ESPTFlushEntryVec * entry = &espt_state.espt_entry;
	int r = -1;	

	espt_entry.flush_entry.list = entry->addr_list;
	espt_entry.flush_entry.size = entry->size;
	espt_entry.flush_entry.pid = getpid();
	
	r = espt_ioctl(ESPT_FLUSH_ENTRY, &espt_entry);
	if(r)
		goto out;

	g_free(entry->addr_list);
	espt_entry_list_init();
	r = 0;
out:
	return r;
}

static bool espt_check_overlap(uint64_t start, uint64_t size){
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (!((start + size <= var->guest_phys_addr) ||
		      (start >= var->guest_phys_addr + var->memory_size))) {
			return true;
        }
	}
	return false;
}

static ESPTMemorySlot * espt_alloc_slot(uint64_t start, uint64_t size, void * ram)
{
	ESPTMemorySlot * mem = (ESPTMemorySlot *)g_malloc0(sizeof(ESPTMemorySlot));
	mem->memory_size = size;
	mem->guest_phys_addr = start;
	mem->userspace_addr = (unsigned long)ram;
	return mem;
}

static void espt_remove_slot(ESPTMemorySlot *mem)
{
	QLIST_REMOVE(mem, link);
	g_free(mem);
}

static void espt_insert_slot(ESPTMemorySlot *mem)
{
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (var->guest_phys_addr >= mem->guest_phys_addr + mem->memory_size) {
            QLIST_INSERT_AFTER(var, mem, link);
			return;
        }
	}
}

bool espt_find_gpa_in_slot(hwaddr gpa)
{
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (var->guest_phys_addr <= gpa && gpa < var->guest_phys_addr + var->memory_size) {
            return true;
        }
	}
    return false;
}

static ESPTMemorySlot *espt_lookup_matching_slot(hwaddr start_addr,
                                         hwaddr size)
{
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (start_addr == var->guest_phys_addr && size == var->memory_size) {
            return var;
        }
	}
    return NULL;
}

static hwaddr espt_align_section(MemoryRegionSection *section,
                                hwaddr *start)
{
    hwaddr size = int128_get64(section->size);
    hwaddr delta, aligned;

    /* kvm works in page size chunks, but the function may be called
       with sub-page size and unaligned start address. Pad the start
       address to next and truncate size to previous page boundary. */
    aligned = ROUND_UP(section->offset_within_address_space,
                       qemu_real_host_page_size);
    delta = aligned - section->offset_within_address_space;
    *start = aligned;
    if (delta > size) {
        return 0;
    }

    return (size - delta) & qemu_real_host_page_mask;
}

static int espt_set_user_memory_slot(ESPTMemorySlot *mem, bool new){
	int r;

	r = -EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	r = 0;
	if(!new){
		espt_remove_slot(mem);
	}
	else{
		espt_insert_slot(mem);
	}
out:
	return r;
}

static void espt_set_phys_mem(MemoryRegionSection *section, bool add)
{
    ESPTMemorySlot *mem;
    int err;
    MemoryRegion *mr = section->mr;
    hwaddr start_addr, size;
    void *ram;

    if (!memory_region_is_ram(mr)) {
		return;
    }

    size = espt_align_section(section, &start_addr);
    if (!size) {
        return;
    }

    /* use aligned delta to align the ram address */
    ram = memory_region_get_ram_ptr(mr) + section->offset_within_region +
          (start_addr - section->offset_within_address_space);

	if(espt_check_overlap(start_addr, size)){
		qemu_log("mem slot overlap!\n");
	}

    //kvm_slots_lock(kml);

    if (!add) {
		mem = espt_lookup_matching_slot(start_addr, size);
		if (!mem) {
			goto out;
		}

		/* unregister the slot */
		err = espt_set_user_memory_slot(mem, false);
		if (err) {
			fprintf(stderr, "%s: error unregistering slot: %s\n",
					__func__, strerror(-err));
			abort();
		}
        goto out;
    }
	else {
		/* register the new slot */
		mem = espt_alloc_slot(start_addr, size, ram);
		err = espt_set_user_memory_slot(mem, true);
		if (err) {
			fprintf(stderr, "%s: error registering slot: %s\n", __func__,
					strerror(-err));
			abort();
		}
	}
out:
    //kvm_slots_unlock(kml);
	return;
}

static void espt_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    memory_region_ref(section->mr);
    espt_set_phys_mem(section, true);
}

static void espt_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    espt_set_phys_mem(section, false);
    memory_region_unref(section->mr);
}

static void espt_memory_listener_register(AddressSpace *as)
{
	ESPTState *s = &espt_state;
    s->memory_listener.region_add = espt_region_add;
    s->memory_listener.region_del = espt_region_del;
    s->memory_listener.priority = 10;

    memory_listener_register(&s->memory_listener, as);
}

int espt_ioctl(int type, ...)
{
	ESPTState *s = &espt_state;
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(s->fd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}

int espt_init(void)
{
	int ret;
	ESPTState *s = &espt_state;
	espt_entry_list_init();
	s->fd = qemu_open("/dev/espt", O_RDWR);
	if (s->fd == -1) {
        fprintf(stderr, "Could not access espt kernel module: %m\n");
        ret = -errno;
        goto err;
    }
	espt_memory_listener_register(&address_space_memory);
	return 0;
err:
	assert(ret < 0);
	if (s->fd != -1) {
		close(s->fd);
	}
	
    return ret;
}


