/*
  Copyright (c) 2015 Peter Dinda

  Library for accessing Linux abstract page table information
  and transforming this information into other forms.
*/

#ifndef __pt_scan
#define __pt_scan

#include <stdio.h>
#include <stdint.h>


union page_entry {
    uint64_t val;
    struct {
	uint64_t pfn:55; 	// if swapped, then 5 bits of type, 50 buts of offset
	uint64_t pageshift:6;
	uint64_t anon:1;
	uint64_t swapped:1;
	uint64_t present:1;
    } __attribute__((packed)) fields;
} __attribute__((packed));

union page_flags { 
    uint64_t val;
    struct {
	uint64_t LOCKED:1; 
	uint64_t ERROR:1;
	uint64_t REFERENCED:1;
	uint64_t UPTODATE:1;
	uint64_t DIRTY:1;
	uint64_t LRU:1;
	uint64_t ACTIVE:1;
	uint64_t SLAB:1;
	uint64_t WRITEBACK:1;
	uint64_t RECLAIM:1;
	uint64_t BUDDY:1;
	uint64_t MMAP:1;
	uint64_t ANON:1;
	uint64_t SWAPCACHE:1;
	uint64_t SWAPBACKED:1;
	uint64_t COMPOUND_HEAD:1;
	uint64_t COMPOUND_TAIL:1;
	uint64_t HUGE:1;
	uint64_t UNEVICTABLE:1;
	uint64_t HWPOISON:1;
	uint64_t NOPAGE:1;
	uint64_t KSM:1;
	uint64_t THP:1;
	uint64_t BALLOON:1;
	uint64_t ZERO_PAGE:1;
    } __attribute__((packed)) flags;
} __attribute__((packed)); 

struct page_info {
    uint64_t          va;
    union page_entry  pme;
    uint64_t          refcount;
    union page_flags  flags;
};

struct mmap_entry {
    uint64_t          va_start;
    uint64_t          pa_start;
    uint64_t          num_pages;
    uint64_t          flags;
} ;

#define PAGE_SIZE 4096


// input: num_pages = number of available slots
// output num_pages = number of slots used
// pi = NULL => just count number of page_infos needed
int pt_scan_get_page_infos_region(int pid, uint64_t valow, uint64_t vahigh, struct page_info *pi, uint64_t *num_pages);
int pt_scan_get_page_infos_all_maps(int pid, struct page_info *pi, uint64_t *num_pages);

int pt_scan_print_page_infos(FILE *out, struct page_info *pi, uint64_t num_pages);

// Convert to compacted (RLE) mmap array
// me = NULL => just count number of mmap_entries needed
int pt_scan_page_infos_to_mmap_entries(struct page_info *pi, uint64_t num_pages, struct mmap_entry *me, uint64_t *num_me);

int pt_scan_print_mmap_entries(FILE *out, struct mmap_entry *me, uint64_t num_me);

int pt_scan_write_mmap_entries(int fd, struct mmap_entry *me, uint64_t num_me);
int pt_scan_map_mmap_entries(int fd, void *target, struct mmap_entry **me, uint64_t *num_me);

#endif
