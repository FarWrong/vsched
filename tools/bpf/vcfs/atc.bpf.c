// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//#include <linux/sched.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/sched.h>

#define per_cpu_ptr(ptr, cpu)   ({ (void)(cpu); (ptr); })
#define per_cpu(var, cpu)	(*per_cpu_ptr(&(var), cpu))


__u64 out__runqueues_addr = -1;
__u64 out__bpf_prog_active_addr = -1;
__u32 out__rq_cpu = -1; /* percpu struct fields */
int out__bpf_prog_active = -1; /* percpu int */
__u32 out__this_rq_cpu = -1;
int out__this_bpf_prog_active = -1;
__u32 out__cpu_0_rq_cpu = -1; /* cpu_rq(0)->cpu */
extern const struct rq runqueues __ksym; /* struct type global var. */
extern const int bpf_prog_active __ksym; /* int type global var. */


char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned long tgidpid = 0;
unsigned long cgid = 0;
unsigned long allret = 0;
unsigned long max_exec_slice = 0;




int simple_strcmp(const char *s1, const char *s2) {
    while (*s1 == *s2) {
        // If we reach the end of both strings, they are equal
        if (*s1 == '\0') {
            return 0;
        }
        s1++;
        s2++;
    }
    // Return the difference in ASCII values of the first differing characters
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}
#define INVALID_RET ((unsigned long) -1L)

//#define debug(args...) bpf_printk(args)
#define debug(args...)



SEC("sched/cfs_sched_tick_end")
int BPF_PROG(test,struct rq *rq,u64 now)
{
	struct task_struct *curr = rq->curr;
	const char test_str[] = "test string:%llu\n";
	s64 delta_exec;
	if(rq->nr_running>0 && (curr != rq->idle)){
		if(rq->last_preemption !=0){
			delta_exec = (now) - (rq->last_idle_tp);
                        s64 last_time;
                        if((now-delta_exec)>rq->last_preemption){
                                last_time=delta_exec;
                        }else{
                                last_time=now-rq->last_preemption;
                        }
                        //note that there's supposed to be a breakpoint here
                        s64 prev_time_brk;
			if(rq->last_active_time<1200000){
				prev_time_brk = 3000000;
			}else{
				prev_time_brk = (rq->last_active_time)/10 * 8 - 1000000;
			}
			prev_time_brk = 2000000;
			if(prev_time_brk < last_time){
//				if (simple_strcmp(curr->comm, "sysbench") == 0) {
				if (1) {
						if(rq->avg_wakeup_latency != 18446744073709551615){
							bpf_printk("Average Migration-Wakeup latency: %llu",rq->avg_wakeup_latency);
							bpf_printk("average Load: %llu",rq->cfs.avg.load_avg);
							bpf_printk("Last active time: %llu",rq->last_active_time);
							bpf_printk("Last Idle Time: %llu", rq->broadcast_migrate);							}
						return 12000000;
				}
                        }
                }
	}
	return -1;
}

SEC("sched/cfs_select_run_cpu")
int cfs_select_run(const void *ctx)
{
	struct rq *rq;
	rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, 3);
	bpf_printk("Should be 3: %llu", rq->cpu);
	return 0;
}
