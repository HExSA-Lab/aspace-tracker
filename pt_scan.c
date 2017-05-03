/* 
  Copyright (c) 2015 Peter Dinda 
 
  Library for accessing Linux abstract page table information 
  and transforming this information into other forms. 
*/ 
  
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pt_scan.h"
	

static int read_all(int fd, void *buf, int n)
{
    int cur;

    while (n) { 
	cur = read(fd,buf,n);
	if (cur<0) { 
	    return -1;
	} 
	n-=cur;
	buf+=cur;
    }
    return 0;
}

static int write_all(int fd, void *buf, int n)
{
    int cur;

    while (n) { 
	cur = write(fd,buf,n);
	if (cur<0) { 
	    return -1;
	} 
	n-=cur;
	buf+=cur;
    }
    return 0;
}

int pt_scan_get_page_infos_region(int pid, uint64_t valow, uint64_t vahigh, struct page_info *pi, uint64_t *nump)
{
    int pm, pc, pf;
    char buf[80];
    uint64_t offset;
    uint64_t i;
    unsigned num_pages;
    

    num_pages = (vahigh-valow)/PAGE_SIZE; 

    if (!pi) { 
	*nump = num_pages;
	return 0;
    } 

    if (*nump < num_pages) {
	fprintf(stderr,"Not enough rooom\n");
	return 0;
    }

    *nump = num_pages;

    sprintf(buf, "/proc/%d/pagemap", pid);

    pm = open(buf,O_RDONLY);
    pc = open("/proc/kpagecount",O_RDONLY);
    pf = open("/proc/kpageflags",O_RDONLY);

    if (pm<0 || pc<0 || pf<0) { 
	fprintf(stderr,"Cannot open paging files\n");
	goto out_fail;
    }


    offset = (valow/PAGE_SIZE)*sizeof(uint64_t);;

    if (lseek(pm,offset,SEEK_SET)<0) { 
	fprintf(stderr,"Cannot seek for page\n");
	goto out_fail;
    }

    for (i=0;
	 i<num_pages;
	 offset+=sizeof(uint64_t), i++) { 
	pi[i].va = valow+(uint64_t)i*PAGE_SIZE;
	if (read_all(pm,&(pi[i].pme),sizeof(pi[i].pme))) { 
	    fprintf(stderr,"Cannot read from pagemap\n");
	    goto out_fail;
	}
	if (pi[i].pme.fields.swapped) { 
	    pi[i].refcount=0;
	    pi[i].flags.val=0;
	} else {
	    uint64_t pfn_off = sizeof(uint64_t)*pi[i].pme.fields.pfn;
	    if (lseek(pc,pfn_off,SEEK_SET)<0) { 
		fprintf(stderr,"Cannot seek page count\n");
		goto out_fail;
	    }
	    if (read_all(pc,&(pi[i].refcount),sizeof(pi[i].refcount))) { 
		fprintf(stderr,"Cannot read refcount\n");
		goto out_fail;
	    }
	    if (lseek(pf,pfn_off,SEEK_SET)<0) { 
		fprintf(stderr,"Cannot seek page fields\n");
		goto out_fail;
	    }
	    if (read_all(pf,&(pi[i].flags),sizeof(pi[i].flags))) { 
		fprintf(stderr,"Cannot read page fields\n");
		goto out_fail;
	    }
	}
    }

    close(pf);
    close(pc);
    close(pm);

    return 0;

 out_fail:
    close(pf);
    close(pc);
    close(pm);

    return -1;

}

static int print_page_info(FILE *out, struct page_info *pi)
{
    printf("%lx", pi->va);

    if (pi->pme.fields.pfn==0) { 
	fprintf(out,"\t unmapped\n");
	return 0;
    }

    if (pi->pme.fields.swapped) { 
	fprintf(out,"\t(%lx,%lx)",(uint64_t) pi->pme.fields.pfn & 0x1f, (uint64_t) pi->pme.fields.pfn >> 5);
    } else {
	fprintf(out,"\t%lx",(uint64_t) pi->pme.fields.pfn*PAGE_SIZE);
    }

    fprintf(out,"\t%lx",1UL<<pi->pme.fields.pageshift);

    if (pi->pme.fields.anon) { 
	fprintf(out,"\tANON");
    } else {
	fprintf(out,"\tFILE");
    }
    if (pi->pme.fields.swapped) { 
	fprintf(out,"\tSWAP");
    } else {
	fprintf(out,"\tMEM");
    }
    if (pi->pme.fields.present) { 
	fprintf(out,"\tPRESENT");
    } else {
	fprintf(out,"\tABSENT");
    }
    
    if (pi->pme.fields.present) {
	fprintf(out,"\t%lx\t(",pi->refcount);

#define CHK(X) if (pi->flags.flags.X) { fprintf(out," " #X ); }

	CHK(LOCKED); 
	CHK(ERROR);
	CHK(REFERENCED);
	CHK(UPTODATE);
	CHK(DIRTY);
	CHK(LRU);
	CHK(ACTIVE);
	CHK(SLAB);
	CHK(WRITEBACK);
	CHK(RECLAIM);
	CHK(BUDDY);
	CHK(MMAP);
	CHK(ANON);
	CHK(SWAPCACHE);
	CHK(SWAPBACKED);
	CHK(COMPOUND_HEAD);
	CHK(COMPOUND_TAIL);
	CHK(HUGE);
	CHK(UNEVICTABLE);
	CHK(HWPOISON);
	CHK(NOPAGE);
	CHK(KSM);
	CHK(THP);
	CHK(BALLOON);
	CHK(ZERO_PAGE);

	fprintf(out," )");
	
    }
    

    fprintf(out,"\n");
    return 0;
}	    

int pt_scan_print_page_infos(FILE *out, struct page_info *pi, uint64_t num)
{
    uint64_t i;
    
    for (i=0;i<num;i++) {
	if (print_page_info(out,&(pi[i]))) { 
	    return -1;
	}
    }
    
    return 0;
}


int pt_scan_page_infos_to_mmap_entries(struct page_info *pi, uint64_t num_pages, struct mmap_entry *me, uint64_t *num_mes)
{
    uint64_t i;
    uint64_t num_runs=0;
    uint64_t run_next=0;
    uint64_t run_start_va=0;
    uint64_t run_start_pa=0;
    uint64_t run_len=0;
    uint64_t in_run=0;

    for (i=0;i<num_pages;i++) {
	if (pi[i].pme.fields.pfn==0 || !(pi[i].pme.fields.present)) { 
	    // This page is unmapped
	    if (in_run) { 
		// if we are in a run, this means we are at the end of it
		// and are no longer in a run
		if (me) { 
		    //fprintf(stderr,"Run: VA 0x%lx PA 0x%lx Len 0x%lx\n",run_start_va,run_start_pa,run_len);
		    if (num_runs >= *num_mes) { 
			fprintf(stderr,"Not enough space to capture all runs\n");
			return -1;
		    } else {
			me[num_runs].va_start = run_start_va;
			me[num_runs].pa_start = run_start_pa;
			me[num_runs].num_pages = run_len;
			me[num_runs].flags = 0;
		    }
		}
		num_runs++;
		run_next=0;
		in_run=0;
	    } else {
		// no run to end or start
	    }
	} else {
	    // THis page is mapped
	    if (!in_run) {
		// If we are not in a run, we need to start one
		run_start_va = pi[i].va;
		run_start_pa = pi[i].pme.fields.pfn * PAGE_SIZE;
		run_len = 0;
	    } else {
		// if we are in a run, we need to stop it if this page
		// does not belong to it
		if (pi[i].pme.fields.pfn != run_next) { 
		    // We have finished a run and are starting a new one
		    //fprintf(stderr,"Run: VA 0x%lx PA 0x%lx Len 0x%lx\n",run_start_va,run_start_pa,run_len);
		    if (me) {
			if (num_runs >= *num_mes) { 
			    fprintf(stderr,"Not enough space to capture all runs\n");
			    return -1;
			} else {
			    me[num_runs].va_start = run_start_va;
			    me[num_runs].pa_start = run_start_pa;
			    me[num_runs].num_pages = run_len;
			    me[num_runs].flags = 0;
			}
		    }
		    num_runs++;
		    run_start_va = pi[i].va;
		    run_start_pa = pi[i].pme.fields.pfn * PAGE_SIZE;;
		    run_len = 0;
		} 
	    }
	    // we must now ne eitheri n the same run or the next one
	    run_next = pi[i].pme.fields.pfn + 1;
	    in_run = 1;
	    run_len++;
	}
    }

    if (in_run) {
	// the last run continued through to the end of the PI array
	//fprintf(stderr,"Run: VA 0x%lx PA 0x%lx Len 0x%lx\n",run_start_va,run_start_pa,run_len);
	if (me) { 
	    if (num_runs >= *num_mes) { 
		fprintf(stderr,"Not enough space to capture all runs\n");
		return -1;
	    } else {
		me[num_runs].va_start = run_start_va;
		me[num_runs].pa_start = run_start_pa;
		me[num_runs].num_pages = run_len;
		me[num_runs].flags = 0;
	    }
	}
	num_runs++;
    }

    *num_mes = num_runs;

    //fprintf(stderr, "RLE: 0x%lx pages compressed to 0x%lx runs\n", num_pages, num_runs);

    return 0;
}



int pt_scan_get_page_infos_all_maps(int pid, struct page_info *pi, uint64_t *num_pages)
{
    uint64_t valo, vahi, reg_num_pages, total_num_pages;
    char buf[256];
    FILE *f;

    sprintf(buf,"/proc/%d/maps",pid);

    f = fopen(buf,"r");
    
    if (!f) { 
	fprintf(stderr,"Unable to open maps for %d\n",pid);
	return -1;
    }

    total_num_pages = 0;

    while (fgets(buf,256,f)) { 
	if (sscanf(buf,"%lx-%lx",&valo,&vahi)==2) { 
	    if (valo>=0x800000000000UL || vahi>=0x800000000000UL) {
		// user mode maps only (no vsyscall)
		// should probably also ignore VDSO here
		break;
	    }
	    if (!pi) {
		if (pt_scan_get_page_infos_region(pid,valo,vahi,0,&reg_num_pages)) { 
		    fprintf(stderr,"failed to handle region\n");
		    fclose(f);
		    return -1;
		}
		total_num_pages += reg_num_pages;
	    } else {
		reg_num_pages = *num_pages - total_num_pages;
		if (pt_scan_get_page_infos_region(pid,valo,vahi,&(pi[total_num_pages]),&reg_num_pages)) { 
		    fprintf(stderr,"failed to handle region\n");
		    fclose(f);
		    return -1;
		}
		total_num_pages += reg_num_pages;
	    }
	}
    }

    *num_pages = total_num_pages;

    fclose(f);

    return  0;
}


int pt_scan_print_mmap_entries(FILE *out, struct mmap_entry *me, uint64_t num)
{
    uint64_t i;
    
    for (i=0;i<num;i++) {
	fprintf(stderr,"0x%lx\t0x%lx\t0x%lx\t0x%lx\n",
		me[i].va_start,
		me[i].pa_start,
		me[i].num_pages,
		me[i].flags);
    }
   
    return 0;
}

int pt_scan_write_mmap_entries(int fd, struct mmap_entry *me, uint64_t num)
{
    return write_all(fd,me,num*sizeof(struct mmap_entry));
}


int pt_scan_map_mmap_entries(int fd, void *target, struct mmap_entry **me, uint64_t *num)
{
    struct stat s;
    uint64_t len;
    void *m;
    
    if (fstat(fd,&s)<0) { 
	return -1;
    }
    
    len = s.st_size;

    m = mmap(target, 
	     len,
	     PROT_READ | PROT_WRITE,
	     MAP_SHARED,
	     fd,
	     0);

    if (m == MAP_FAILED) { 
	*me = 0;
	*num = 0;
	return -1;
    } else {
	*me = m;
	*num = len/sizeof(struct mmap_entry);
	return 0;
    }
}

