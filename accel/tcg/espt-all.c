#include "sysemu/espt_int.h"

#define PAGE_SIZE qemu_real_host_page_size
#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))

ESPTState espt_state;
extern struct HelperElem helper_elem;

static void espt_entry_list_init(void)
{
	struct ESPTFlushEntryVec * entry = &espt_state.espt_entry;
	
	entry->addr_list = (target_ulong *)g_malloc0_n(16, sizeof(target_ulong));
	entry->capacity = 16;
	entry->size = 0;
}

static void espt_entry_list_insert(target_ulong elem)
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


static void get_iotlb_hva(CPUState *cpu, target_ulong vaddr,
                             hwaddr paddr, MemTxAttrs attrs, int prot,
                             int mmu_idx, target_ulong size, hwaddr *my_iotlb, uintptr_t *my_addend)
{	hwaddr iotlb, xlat, sz, paddr_page;
	paddr_page = paddr & TARGET_PAGE_MASK;
	MemoryRegionSection *section;
	int asidx = cpu_asidx_from_attrs(cpu, attrs);
	bool is_ram, is_romd;
	uintptr_t addend;

	if (size <= TARGET_PAGE_SIZE) {
        sz = TARGET_PAGE_SIZE;
    } else {
        sz = size;
    }
	
	section = address_space_translate_for_iotlb(cpu, asidx, paddr_page,
                                                &xlat, &sz, attrs, &prot);
	
	is_ram = memory_region_is_ram(section->mr);
    is_romd = memory_region_is_romd(section->mr);
	
	if (is_ram || is_romd) {
        /* RAM and ROMD both have associated host memory. */
        addend = (uintptr_t)memory_region_get_ram_ptr(section->mr) + xlat;
    } else {
        /* I/O does not; force the host address to NULL. */
        addend = 0;
    }

    if (is_ram) {
        iotlb = memory_region_get_ram_addr(section->mr) + xlat;
        /*
         * Computing is_clean is expensive; avoid all that unless
         * the page is actually writable.
         */
    } else {
        /* I/O or ROMD */
        iotlb = memory_region_section_get_iotlb(cpu, section) + xlat;
        /*
         * Writes to romd devices must go through MMIO to enable write.
         * Reads to romd devices go through the ram_ptr found above,
         * but of course reads to I/O must go through MMIO.
         */
    }
	*my_iotlb = iotlb;
	*my_addend = addend;
	
}

#if !defined(CONFIG_USER_ONLY)
static hwaddr get_hphys(CPUState *cs, hwaddr gphys, MMUAccessType access_type,
                        int *prot)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    uint64_t rsvd_mask = PG_HI_RSVD_MASK;
    uint64_t ptep, pte;
    uint64_t exit_info_1 = 0;
    target_ulong pde_addr, pte_addr;
    uint32_t page_offset;
    int page_size;

    if (likely(!(env->hflags2 & HF2_NPT_MASK))) {
        return gphys;
    }

    if (!(env->nested_pg_mode & SVM_NPT_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (env->nested_pg_mode & SVM_NPT_PAE) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->nested_pg_mode & SVM_NPT_LMA) {
            uint64_t pml5e;
            uint64_t pml4e_addr, pml4e;

            pml5e = env->nested_cr3;
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;

            pml4e_addr = (pml5e & PG_ADDRESS_MASK) +
                    (((gphys >> 39) & 0x1ff) << 3);
            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pml4e_addr, pml4e);
            }
            ptep &= pml4e ^ PG_NX_MASK;
            pdpe_addr = (pml4e & PG_ADDRESS_MASK) +
                    (((gphys >> 30) & 0x1ff) << 3);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            pdpe_addr = (env->nested_cr3 & ~0x1f) + ((gphys >> 27) & 0x18);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        pde_addr = (pdpe & PG_ADDRESS_MASK) + (((gphys >> 21) & 0x1ff) << 3);
        pde = x86_ldq_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }
        pte_addr = (pde & PG_ADDRESS_MASK) + (((gphys >> 12) & 0x1ff) << 3);
        pte = x86_ldq_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */
        ptep &= pte ^ PG_NX_MASK;
        page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = (env->nested_cr3 & ~0xfff) + ((gphys >> 20) & 0xffc);
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = (pde & ~0xfff) + ((gphys >> 10) & 0xffc);
        pte = x86_ldl_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        page_size = 4096;
        rsvd_mask = 0;
    }

 do_check_protect:
    rsvd_mask |= (page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
 do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    if (!(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }
    if (ptep & PG_NX_MASK) {
        if (access_type == MMU_INST_FETCH) {
            goto do_fault_protect;
        }
        *prot &= ~PAGE_EXEC;
    }
    if (!(ptep & PG_RW_MASK)) {
        if (access_type == MMU_DATA_STORE) {
            goto do_fault_protect;
        }
        *prot &= ~PAGE_WRITE;
    }

    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = gphys & (page_size - 1);
    return pte + page_offset;

 do_fault_rsvd:
    exit_info_1 |= SVM_NPTEXIT_RSVD;
 do_fault_protect:
    exit_info_1 |= SVM_NPTEXIT_P;
 do_fault:
    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 gphys);
    exit_info_1 |= SVM_NPTEXIT_US;
    if (access_type == MMU_DATA_STORE) {
        exit_info_1 |= SVM_NPTEXIT_RW;
    } else if (access_type == MMU_INST_FETCH) {
        exit_info_1 |= SVM_NPTEXIT_ID;
    }
    if (prot) {
        exit_info_1 |= SVM_NPTEXIT_GPA;
    } else { /* page table access */
        exit_info_1 |= SVM_NPTEXIT_GPT;
    }
    cpu_vmexit(env, SVM_EXIT_NPF, exit_info_1, env->retaddr);
}

static int handle_espt_mmu_fault(CPUState *cs, vaddr addr, int size,
                            int is_write1, int mmu_idx, hwaddr *my_paddr, hwaddr *iotlb, uintptr_t *addend)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    uint64_t ptep, pte;
    int32_t a20_mask;
    target_ulong pde_addr, pte_addr;
    int error_code = 0;
    int is_dirty, prot, page_size, is_write, is_user;
    hwaddr paddr;
    uint64_t rsvd_mask = PG_HI_RSVD_MASK;
    uint32_t page_offset;
    target_ulong vaddr;

    is_user = mmu_idx == MMU_USER_IDX;
#if defined(DEBUG_MMU)
    printf("MMU fault: addr=%" VADDR_PRIx " w=%d u=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, is_user, env->eip);
#endif
    is_write = is_write1 & 1;

    a20_mask = x86_get_a20_mask(env);
    if (!(env->cr[0] & CR0_PG_MASK)) {
        pte = addr;
#ifdef TARGET_X86_64
        if (!(env->hflags & HF_LMA_MASK)) {
            /* Without long mode we can only address 32bits in real mode */
            pte = (uint32_t)pte;
        }
#endif
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        page_size = 4096;
        goto do_mapping;
    }

    if (!(env->efer & MSR_EFER_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (env->cr[4] & CR4_PAE_MASK) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = env->cr[4] & CR4_LA57_MASK;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                env->error_code = 0;
                cs->exception_index = EXCP0D_GPF;
                return 1;
            }

            if (la57) {
                pml5e_addr = ((env->cr[3] & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e_addr = get_hphys(cs, pml5e_addr, MMU_DATA_STORE, NULL);
                pml5e = x86_ldq_phys(cs, pml5e_addr);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    goto do_fault;
                }
                if (pml5e & (rsvd_mask | PG_PSE_MASK)) {
                    goto do_fault_rsvd;
                }
                if (!(pml5e & PG_ACCESSED_MASK)) {
                    pml5e |= PG_ACCESSED_MASK;
                    x86_stl_phys_notdirty(cs, pml5e_addr, pml5e);
                }
                ptep = pml5e ^ PG_NX_MASK;
            } else {
                pml5e = env->cr[3];
                ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e_addr = get_hphys(cs, pml4e_addr, MMU_DATA_STORE, false);
            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pml4e_addr, pml4e);
            }
            ptep &= pml4e ^ PG_NX_MASK;
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) &
                a20_mask;
            pdpe_addr = get_hphys(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            /* XXX: load them when cr3 is loaded ? */
            pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe_addr = get_hphys(cs, pdpe_addr, MMU_DATA_STORE, false);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) &
            a20_mask;
        pde_addr = get_hphys(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldq_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }
        pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) &
            a20_mask;
        pte_addr = get_hphys(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldq_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */
        ptep &= pte ^ PG_NX_MASK;
        page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & 0xffc)) &
            a20_mask;
        pde_addr = get_hphys(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) &
            a20_mask;
        pte_addr = get_hphys(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldl_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        page_size = 4096;
        rsvd_mask = 0;
    }

do_check_protect:
    rsvd_mask |= (page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || (!is_user && !(env->cr[0] & CR0_WP_MASK))) {
            prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((env->cr[4] & CR4_SMEP_MASK) && (ptep & PG_USER_MASK)))) {
        prot |= PAGE_EXEC;
    }
    if ((env->cr[4] & CR4_PKE_MASK) && (env->hflags & HF_LMA_MASK) &&
        (ptep & PG_USER_MASK) && env->pkru) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkru_ad = (env->pkru >> pk * 2) & 1;
        uint32_t pkru_wd = (env->pkru >> pk * 2) & 2;
        uint32_t pkru_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkru_ad) {
            pkru_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkru_wd && (is_user || env->cr[0] & CR0_WP_MASK)) {
            pkru_prot &= ~PAGE_WRITE;
        }

        prot &= pkru_prot;
        if ((pkru_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        prot &= ~PAGE_WRITE;
    }

 do_mapping:
    pte = pte & a20_mask;

    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = addr & (page_size - 1);
    paddr = get_hphys(cs, pte + page_offset, is_write1, &prot);
	*my_paddr = paddr;
    /* Even if 4MB pages, we map only one 4KB page in the cache to
       avoid filling it too fast */
    vaddr = addr & TARGET_PAGE_MASK;
    paddr &= TARGET_PAGE_MASK;

    assert(prot & (1 << is_write1));
    get_iotlb_hva(cs, vaddr, paddr, cpu_get_mem_attrs(env),
                            prot, mmu_idx, page_size, iotlb, addend);
    return 0;
 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((env->efer & MSR_EFER_NXE) &&
          (env->cr[4] & CR4_PAE_MASK)) ||
         (env->cr[4] & CR4_SMEP_MASK)))
        error_code |= PG_ERROR_I_D_MASK;
    if (env->intercept_exceptions & (1 << EXCP0E_PAGE)) {
        /* cr2 is not modified in case of exceptions */
        x86_stq_phys(cs,
                 env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 addr);
    } else {
        env->cr[2] = addr;
    }
    env->error_code = error_code;
    cs->exception_index = EXCP0E_PAGE;
    return 1;
}

static bool handle_espt_page_fault(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      uintptr_t retaddr, hwaddr *paddr, hwaddr *iotlb, uintptr_t *addend)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    env->retaddr = retaddr;
    if (handle_espt_mmu_fault(cs, addr, size, access_type, mmu_idx, paddr, iotlb, addend)) {
        /* FIXME: On error in get_hphys we have already jumped out.  */
        raise_exception_err_ra(env, cs->exception_index,
                               env->error_code, retaddr);
    }
    return true;
}
#endif

static void espt_insert_slot(ESPTMemorySlot *mem){
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (mem->guest_phys_addr + mem->memory_size > var->guest_phys_addr) {
            QLIST_INSERT_AFTER(mem, var, link);
			return;
        }
	}
}

static bool espt_find_gpa_in_slot(hwaddr gpa)
{
	ESPTState *s = &espt_state;
	ESPTMemorySlot *var, *next_var;
	QLIST_FOREACH_SAFE(var, &s->memory_slot, link, next_var){
		if (var->guest_phys_addr <= gpa && gpa <= var->guest_phys_addr + var->memory_size) {
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

static int espt_mem_flags(MemoryRegion *mr)
{
    bool readonly = mr->readonly || memory_region_is_romd(mr);
    int flags = 0;

    if (memory_region_get_dirty_log_mask(mr) != 0) {
        flags |= ESPT_MEM_LOG_DIRTY_PAGES;
    }
    if (readonly) {
        flags |= ESPT_MEM_READONLY;
    }
    return flags;
}

static int espt_get_dirty_pages_log_range(MemoryRegionSection *section,
                                         unsigned long *bitmap)
{
    ram_addr_t start = section->offset_within_region +
                       memory_region_get_ram_addr(section->mr);
    ram_addr_t pages = int128_get64(section->size) / qemu_real_host_page_size;

    cpu_physical_memory_set_dirty_lebitmap(bitmap, start, pages);
    return 0;
}

static void espt_memslot_init_dirty_bitmap(ESPTMemorySlot *mem)
{
    /*
     * XXX bad kernel interface alert
     * For dirty bitmap, kernel allocates array of size aligned to
     * bits-per-long.  But for case when the kernel is 64bits and
     * the userspace is 32bits, userspace can't align to the same
     * bits-per-long, since sizeof(long) is different between kernel
     * and user space.  This way, userspace will provide buffer which
     * may be 4 bytes less than the kernel will use, resulting in
     * userspace memory corruption (which is not detectable by valgrind
     * too, in most cases).
     * So for now, let's align to 64 instead of HOST_LONG_BITS here, in
     * a hope that sizeof(long) won't become >8 any time soon.
     */
    hwaddr bitmap_size = ALIGN(((mem->memory_size) >> TARGET_PAGE_BITS),
                                        /*HOST_LONG_BITS*/ 64) / 8;
    mem->dirty_bitmap = g_malloc0(bitmap_size);
}

static int espt_physical_sync_dirty_bitmap(MemoryRegionSection *section)
{
    ESPTMemorySlot *mem;
    hwaddr start_addr, size;
    int ret = 0;

    size = espt_align_section(section, &start_addr);
	MemoryRegionSection subsection = *section;

	mem = espt_lookup_matching_slot(start_addr, size);
	if (!mem) {
		/* We don't have a slot if we want to trap every access. */
		goto out;
	}

	if (!mem->dirty_bitmap) {
		/* Allocate on the first log_sync, once and for all */
		espt_memslot_init_dirty_bitmap(mem);
	}
	subsection.offset_within_region = size;
	subsection.size = int128_make64(size);
	espt_get_dirty_pages_log_range(&subsection, mem->dirty_bitmap);
	
out:
    return ret;
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
		QLIST_REMOVE(mem, link);
		g_free(mem);
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
    bool writeable = !mr->readonly && !mr->rom_device;
    hwaddr start_addr, size;
    void *ram;

    if (!memory_region_is_ram(mr)) {
        if (writeable) {
            return;
        } else if (!mr->romd_mode) {
            /* If the memory device is not in romd_mode, then we actually want
             * to remove the kvm memory slot so all accesses will trap. */
            add = false;
        }
    }

    size = espt_align_section(section, &start_addr);
    if (!size) {
        return;
    }

    /* use aligned delta to align the ram address */
    ram = memory_region_get_ram_ptr(mr) + section->offset_within_region +
          (start_addr - section->offset_within_address_space);

    //kvm_slots_lock(kml);

    if (!add) {
		mem = espt_lookup_matching_slot(start_addr, size);
		if (!mem) {
			goto out;
		}
		if (mem->flags & ESPT_MEM_LOG_DIRTY_PAGES) {
			espt_physical_sync_dirty_bitmap(section);
		}

		/* unregister the slot */
		g_free(mem->dirty_bitmap);
		mem->dirty_bitmap = NULL;
		mem->memory_size = 0;
		mem->flags = 0;
		err = espt_set_user_memory_slot(mem, false);
		if (err) {
			fprintf(stderr, "%s: error unregistering slot: %s\n",
					__func__, strerror(-err));
			abort();
		}
        goto out;
    }

    /* register the new slot */
	mem = (ESPTMemorySlot *)g_malloc0(sizeof(ESPTMemorySlot));
	mem->memory_size = size;
	mem->guest_phys_addr = start_addr;
	mem->userspace_addr = (unsigned long)ram;
	mem->flags = espt_mem_flags(mr);

	/*if (mem->flags & ESPT_MEM_LOG_DIRTY_PAGES) {
	
		  Reallocate the bmap; it means it doesn't disappear in
		  middle of a migrate.

		  espt_memslot_init_dirty_bitmap(mem);
	}*/

	espt_memslot_init_dirty_bitmap(mem);
	err = espt_set_user_memory_slot(mem, true);
	if (err) {
		fprintf(stderr, "%s: error registering slot: %s\n", __func__,
				strerror(-err));
		abort();
	}

out:
    //kvm_slots_unlock(kml);
	return;
}

static uint64_t io_readx(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                         int mmu_idx, target_ulong addr, uintptr_t retaddr,
                         MMUAccessType access_type, MemOp op)
{
    CPUState *cpu = env_cpu(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    uint64_t val;
    bool locked = false;
    MemTxResult r;

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
    cpu->mem_io_pc = retaddr;
    if (!cpu->can_do_io) {
        cpu_io_recompile(cpu, retaddr);
    }

    if (mr->global_locking && !qemu_mutex_iothread_locked()) {
        qemu_mutex_lock_iothread();
        locked = true;
    }
    r = memory_region_dispatch_read(mr, mr_offset, &val, op, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, memop_size(op), access_type,
                               mmu_idx, iotlbentry->attrs, r, retaddr);
    }
    if (locked) {
        qemu_mutex_unlock_iothread();
    }

    return val;
}

static void io_writex(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                      int mmu_idx, uint64_t val, target_ulong addr,
                      uintptr_t retaddr, MemOp op)
{
    CPUState *cpu = env_cpu(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    bool locked = false;
    MemTxResult r;

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
    if (!cpu->can_do_io) {
        cpu_io_recompile(cpu, retaddr);
    }
    cpu->mem_io_pc = retaddr;

    if (mr->global_locking && !qemu_mutex_iothread_locked()) {
        qemu_mutex_lock_iothread();
        locked = true;
    }
    r = memory_region_dispatch_write(mr, mr_offset, val, op, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, memop_size(op),
                               MMU_DATA_STORE, mmu_idx, iotlbentry->attrs, r,
                               retaddr);
    }
    if (locked) {
        qemu_mutex_unlock_iothread();
    }
}

void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_memory_slot *memslot = 0;
	unsigned long rel_gfn;

	for (i = 0; i < kvm->nmemslots; ++i) {
		memslot = &kvm->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages) {

			if (!memslot || !memslot->dirty_bitmap)
				return;

			rel_gfn = gfn - memslot->base_gfn;

			/* avoid RMW */
			if (!test_bit(rel_gfn, memslot->dirty_bitmap))
				set_bit(rel_gfn, memslot->dirty_bitmap);
			return;
		}
	}
}

void sigsegv_handler(int sig){
	CPUArchState *env = helper_elem.env;
	target_ulong vaddr = helper_elem.addr;
	TCGMemOpIdx oi = helper_elem.oi;
	uintptr_t retaddr = helper_elem.retaddr;
	MemOp op = helper_elem.op;
	bool code_read = helper_elem.code_read;
	uint64_t write_val = helper_elem.write_val;
	bool is_load = helper_elem.is_load;

	int pid = getpid();
	uintptr_t mmu_idx = get_mmuidx(oi);
	MMUAccessType access_type =
        code_read ? MMU_INST_FETCH : MMU_DATA_LOAD;
	size_t size = memop_size(op);
	CPUIOTLBEntry iotlbentry;
	struct ESPTEntry espt_entry;
	
	//extern asmlinkage void espt_vmx_return(void);
	
	hwaddr paddr, iotlb;
	uintptr_t addend, hva;
	
	if(!is_load)
		access_type = MMU_DATA_STORE;
	
	assert(handle_espt_page_fault(env_cpu(env), vaddr, size,
		access_type, mmu_idx, retaddr, &paddr, &iotlb, &addend));				//gva to gpa
		
	iotlbentry.addr = iotlb - (vaddr & TARGET_PAGE_MASK);
	iotlbentry.attrs = cpu_get_mem_attrs(env);
	
	if(!espt_find_gpa_in_slot(paddr)){	//try to find gpa in tcg_memory_region //MMIO
		if(is_load){
			uint64_t read_value = io_readx(env, &iotlbentry, mmu_idx, vaddr, retaddr,
                        access_type, op);}
		else{
			io_writex(env, &iotlbentry, mmu_idx, write_val, vaddr,
						retaddr, op);}
		//espt_vmx_return(); //todo
	}		
	else{
		hva = (uintptr_t)vaddr + addend;
		espt_entry.set_entry.gva = vaddr;
		espt_entry.set_entry.hva = hva;
		espt_entry.set_entry.pid = pid;
		if(!espt_ioctl(ESPT_SET_ENTRY, &espt_entry))
			espt_entry_list_insert(vaddr);
		if(!is_load){
			mark_page_dirty
		}
	}
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


