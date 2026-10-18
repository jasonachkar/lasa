// SPDX-License-Identifier: MIT
// Metadata only. No payloads, arguments, environments or executable filenames.
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0
struct task_struct { int tgid; struct task_struct *real_parent; __u64 start_boottime; } __attribute__((preserve_access_index));
struct event { __u64 timestamp_ns, start_ns; __u32 tgid, tid, uid, ppid, kind; __s32 result; __u64 flags; __u16 family, port; __u8 address[16]; char comm[16]; };
_Static_assert(sizeof(struct event) == 88, "event ABI drift");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } dropped SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u64); __type(value, __u64); } namespace_flags SEC(".maps");
static __always_inline struct event *new_event(__u32 kind) {
 struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
 if (!e) { __u32 key=0; __u64 *lost=bpf_map_lookup_elem(&dropped,&key); if(lost) (*lost)++; return 0; }
 __builtin_memset(e,0,sizeof(*e));
 __u64 id=bpf_get_current_pid_tgid();e->timestamp_ns=bpf_ktime_get_boot_ns();e->tgid=id>>32;e->tid=(__u32)id;e->uid=(__u32)bpf_get_current_uid_gid();e->kind=kind;
 struct task_struct *task=(void*)bpf_get_current_task();
 e->start_ns=BPF_CORE_READ(task,start_boottime);e->ppid=BPF_CORE_READ(task,real_parent,tgid);
 bpf_get_current_comm(e->comm,sizeof(e->comm));return e;
}
struct sys_enter { __u64 common; __s64 id; __u64 args[6]; };
struct sys_exit { __u64 common; __s64 id; __s64 ret; };
SEC("tracepoint/sched/sched_process_exec") int process_exec(void *ctx) {struct event *e=new_event(1);if(e)bpf_ringbuf_submit(e,0);return 0;}
static __always_inline int endpoint(struct sys_enter *ctx,__u32 kind) {
 struct { __u16 family; __u8 data[26]; } addr={};
 // Read only family first, then exactly the relevant sockaddr bytes.
 void *p=(void*)ctx->args[1];__u64 length=ctx->args[2];if(length<2)return 0;
 if(bpf_probe_read_user(&addr.family,2,p))return 0;
 if(addr.family!=2&&addr.family!=10)return 0;
 if(addr.family==2) {if(length<16||bpf_probe_read_user(&addr,16,p))return 0;}
 else {if(length<28||bpf_probe_read_user(&addr,28,p))return 0;}
 struct event *e=new_event(kind);if(!e)return 0;e->family=addr.family;e->port=((__u16)addr.data[0]<<8)|addr.data[1];
 if(addr.family==2)__builtin_memcpy(e->address,&addr.data[2],4);else __builtin_memcpy(e->address,&addr.data[6],16);
 bpf_ringbuf_submit(e,0);return 0;
}
SEC("tracepoint/syscalls/sys_enter_connect") int connect_attempt(struct sys_enter *ctx){return endpoint(ctx,2);}
SEC("tracepoint/syscalls/sys_enter_bind") int bind_attempt(struct sys_enter *ctx){return endpoint(ctx,3);}
SEC("tracepoint/syscalls/sys_exit_accept4") int accepted4(struct sys_exit *ctx){if(ctx->ret<0)return 0;struct event *e=new_event(4);if(e){e->result=(__s32)ctx->ret;bpf_ringbuf_submit(e,0);}return 0;}
SEC("tracepoint/syscalls/sys_exit_accept") int accepted(struct sys_exit *ctx){return accepted4(ctx);}
SEC("tracepoint/syscalls/sys_enter_unshare") int namespace_enter(struct sys_enter *ctx){__u64 id=bpf_get_current_pid_tgid(),flags=ctx->args[0];if(!(flags&0x7e020080ULL))return 0;if(bpf_map_update_elem(&namespace_flags,&id,&flags,BPF_ANY)){__u32 key=0;__u64 *lost=bpf_map_lookup_elem(&dropped,&key);if(lost)(*lost)++;}return 0;}
SEC("tracepoint/syscalls/sys_exit_unshare") int namespace_exit(struct sys_exit *ctx){__u64 id=bpf_get_current_pid_tgid();__u64 *f=bpf_map_lookup_elem(&namespace_flags,&id);if(!f)return 0;__u64 flags=*f;bpf_map_delete_elem(&namespace_flags,&id);if(ctx->ret!=0)return 0;struct event *e=new_event(5);if(e){e->flags=flags;bpf_ringbuf_submit(e,0);}return 0;}
char LICENSE[] SEC("license")="Dual MIT/GPL";
