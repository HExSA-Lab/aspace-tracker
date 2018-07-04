#ifndef __KZPARMS_H__
#define __KZPARMS_H__


typedef enum {
    ZP_MSG_INIT,    // register the process
    ZP_MSG_ACK,     // bidirectional ack 
    ZP_MSG_REG,     // register a new zero page
    ZP_MSG_START,   // start watching for PTE updates
    ZP_MSG_RESET,   // reset for another process (sent when user-space portion dies)
    ZP_MSG_PROMOTE, // (to user) zero page promotion
    ZP_MSG_NEW,     // (to user) new zero page mapping created
    ZP_MSG_DATA,    // (to user) initial page table data
    ZP_MSG_PTRESUME, // resume page table read and data transfer
    ZP_MSG_PTPAUSE,  // (to user) paused page table trace 
} zp_msg_type_t;


typedef struct {

    /* this *must* be first */
    zp_msg_type_t type;
    void *arg;

} __attribute__((packed)) zp_msg_t; 

struct start_msg_arg {
    void *pid;
    void *buff;
};

//strucutred used for storing ptable data
typedef struct {
    uint64_t va;
    uint64_t pa;
} pt_data;


#define KMOD_NAME "kztrace"
#define VERSION "0.0.1"

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

#endif /* !__KZPARMS_H__! */
