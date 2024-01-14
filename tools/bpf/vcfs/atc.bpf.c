// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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

/*
SEC("sched/cfs_check_preempt_wakeup")
int BPF_PROG(wakeup, struct task_struct *curr, struct task_struct *p)
{
	unsigned long tgidpid1, tgidpid2;
	int ret = 0;

	if (allret)
		return allret;

	if (tgidpid) {
		tgidpid1 = (unsigned long)curr->tgid << 32 | curr->pid;
		tgidpid2 = (unsigned long)p->tgid << 32 | p->pid;

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;
		else if ((tgidpid2 & tgidpid) == tgidpid)
			ret = 1;

		if (ret) {
			debug("wakeup1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("wakeup2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("wakeup ret %d", ret);
		}
	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(&curr->se, cgid))
			ret = -1;
		else if (bpf_sched_entity_belongs_to_cgrp(&p->se, cgid))
			ret = 1;

		if (ret) {
			tgidpid1 = (unsigned long)curr->tgid << 32 | curr->pid;
			tgidpid2 = (unsigned long)p->tgid << 32 | p->pid;

			debug("wakeup1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("wakeup2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("wakeup ret %d", ret);
		}
	}
	return ret;
}
*/

/*
SEC("sched/cfs_wakeup_preempt_entity")
int BPF_PROG(preempt_entity, struct sched_entity *curr, struct sched_entity *se)
{
	int ret = 0;

	if (allret)
		return allret;

	if (curr == NULL || se == NULL)
		return 0;
	if (tgidpid) {
		unsigned long tgidpid1, tgidpid2;

		tgidpid1 = bpf_sched_entity_to_tgidpid(curr);
		tgidpid2 = bpf_sched_entity_to_tgidpid(se);

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;
		else if ((tgidpid2 & tgidpid) == tgidpid)
			ret = 1;

		if (ret) {
			debug("entity1 tgid %d pid %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF);
			debug("entity2 tgid %d pid %d", tgidpid2 >> 32,
				   tgidpid2 & 0xFFFFFFFF);
			debug("entity ret %d", ret);
		}

	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(curr, cgid))
			ret = -1;
		else if (bpf_sched_entity_belongs_to_cgrp(se, cgid))
			ret = 1;

		if (ret) {
			debug("entity cg %lu", bpf_sched_entity_to_cgrpid(curr));
			debug("entity cg %lu", bpf_sched_entity_to_cgrpid(se));
			debug("entity cg %d", ret);
		}
	}

	return ret;
}
*/

/*
SEC("sched/cfs_check_preempt_tick")
int BPF_PROG(tick, struct sched_entity *curr, unsigned long delta_exec)
{
	unsigned long tgidpid1;
	int ret = 0;

	if (delta_exec > max_exec_slice)
		return 0;

	if (allret)
		return allret;

	if (curr == NULL)
		return 0;

	if (tgidpid) {
		tgidpid1 = bpf_sched_entity_to_tgidpid(curr);

		if ((tgidpid1 & tgidpid) == tgidpid)
			ret = -1;

		if (ret)
			debug("tick tgid %d pid %d ret %d", tgidpid1 >> 32,
				   tgidpid1 & 0xFFFFFFFF, ret);

	} else if (cgid) {
		if (bpf_sched_entity_belongs_to_cgrp(curr, cgid)) {
			ret = -1;
			debug("tick cg %lu %d", bpf_sched_entity_to_cgrpid(curr), ret);
		}
	}

	return ret;
}
*/


SEC("sched/cfs_sched_tick_end")
int BPF_PROG(test,struct rq *rq,u64 now)
{
	struct task_struct *curr = rq->curr;
	const char test_str[] = "test string:%llu\n";
	s64 delta_exec;
//	bpf_trace_printk(test_str,sizeof(test_str),*(long *)(curr->se.vruntime));
	if(rq->nr_running==1 && (curr != rq->idle)){
		if(rq->last_preemption !=0){
			delta_exec = (now) - (rq->last_idle_tp);
                        s64 last_time;
                        if((now-delta_exec)>rq->last_preemption){
                                last_time=delta_exec;
                        }else{
                                last_time=now-rq->last_preemption;
                        }
                        //note that there's supposed to be a breakpoint here
                        s64 prev_time_brk = (rq->last_active_time/10)*7;
			if(69937630 < last_time){
				if (simple_strcmp(curr->comm, "sysbench") == 0) {
						bpf_printk("Now: %llu",now);
						bpf_printk("Last active time: %llu",rq->last_active_time);
						bpf_printk("Last time: %llu",last_time);
						bpf_printk("breakpoint: %llu",prev_time_brk);
						bpf_printk("Current Task: %s\n", curr->comm);
						return 1;
				}
                        }
                }
	}
	return -1;
}

