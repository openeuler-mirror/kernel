// SPDX-License-Identifier: GPL-2.0

#ifndef pr_fmt
# define pr_fmt(fmt) "fast_ipc: " fmt
#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/preempt.h>
#include <linux/sched/signal.h>
#include <linux/fast_ipc.h>
#include <linux/sched/debug.h>

#define IPC_DEBUG(fmt, ...)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yangyun");
MODULE_DESCRIPTION("fast ipc");
MODULE_VERSION("1.0");

static inline void bind_info_lock(struct fast_ipc_bind_info *bind_info)
{
	spin_lock(&bind_info->lock);
}

static inline void bind_info_unlock(struct fast_ipc_bind_info *bind_info)
{
	spin_unlock(&bind_info->lock);
}

static inline int fast_ipc_check_task_consistency(struct task_struct *client,
		struct task_struct *server)
{
	if (client->pid == server->pid) {
		pr_err("error: client(%s/%d) and server(%s/%d) is same\n", client->comm,
			   client->pid, server->comm, server->pid);
		return -EPERM;
	}

	return 0;
}

static inline ssize_t
fast_ipc_call_check(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk)
{
	ssize_t ret = 0;
	struct task_struct *server_task;

	if (!bind_info)
		return -ENOENT;

	if (bind_info->client_task) {
		pr_err("error: bind already with client task: %s/%d, current is : %s/%d",
			   bind_info->client_task->comm, bind_info->client_task->pid,
			   tsk->comm, tsk->pid);
		return -EEXIST;
	}

	server_task = bind_info->server_task;
	if (!server_task) {
		pr_err("error: server thread is not exsit\n");
		return -ESRCH;
	}

	return ret;
}

static inline void fast_ipc_client_init(
		struct fast_ipc_bind_info *bind_info, struct task_struct *tsk)
{
	bind_info->client_task = tsk;
}


static inline void fast_ipc_client_exit(
		struct fast_ipc_bind_info *bind_info, struct task_struct *tsk)
{
	bind_info->client_task = NULL;
}

static inline int fast_ipc_get_client_exit_code(
		const struct fast_ipc_bind_info *bind_info)
{
	return bind_info->client_need_exit ? -ESRCH : 0;
}

static inline void fast_ipc_wakeup_client_task(
		struct fast_ipc_bind_info *bind_info)
{
	struct task_struct *client_task;

	client_task = bind_info->client_task;
	bind_info->client_need_exit = true;
	wake_up_process(client_task);
}

void fast_ipc_wakeup_server_task(struct fast_ipc_bind_info *bind_info)
{
	struct task_struct *server_task;

	server_task = bind_info->server_task;
	bind_info->server_need_exit = true;
	wake_up_process(server_task);
}
EXPORT_SYMBOL_GPL(fast_ipc_wakeup_server_task);

void *fast_ipc_bind(struct task_struct *server_task)
{
	struct fast_ipc_bind_info *bind_info = NULL;

	bind_info = kcalloc(1, sizeof(struct fast_ipc_bind_info), GFP_KERNEL);
	if (!bind_info)
		return ERR_PTR(-ENOMEM);

	bind_info->server_task = server_task;

	return (void *) bind_info;
}
EXPORT_SYMBOL_GPL(fast_ipc_bind);

void fast_ipc_release(struct fast_ipc_bind_info *bind_info)
{
	if (bind_info) {
		if (bind_info->client_task && bind_info->is_calling)
			fast_ipc_wakeup_client_task(bind_info);
		kfree(bind_info);
	}
}
EXPORT_SYMBOL_GPL(fast_ipc_release);

void fast_ipc_unbind(struct fast_ipc_bind_info *bind_info,
		struct task_struct *server_task)
{
	if (bind_info) {
		if (bind_info->server_task == server_task) {
			bind_info->server_task = NULL;
			if (bind_info->client_task && bind_info->is_calling)
				fast_ipc_wakeup_client_task(bind_info);
			kfree(bind_info);
		}
	}

}
EXPORT_SYMBOL_GPL(fast_ipc_unbind);

ssize_t fast_ipc_do_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk)
{
	struct task_struct *server_task;
	ssize_t ret;

	ret = fast_ipc_call_check(bind_info, tsk);
	if (ret) {
		pr_err("fast ipc call check and init failed, errno: %ld\n", ret);
		return ret;
	}

	fast_ipc_client_init(bind_info, tsk);

	server_task = bind_info->server_task;

	bind_info->client_need_exit = false;
	bind_info->is_calling = true;

	preempt_disable(); /* optimize performance if preemption occurs */
	smp_mb();
	wake_up_process(server_task);
	preempt_enable();
	IPC_DEBUG("[cpu/%d][%s/%d]  ipc do call server(%s/%d)\n",
			  smp_processor_id(), tsk->comm, tsk->pid, server_task->comm,
			  server_task->pid);

	set_current_state(TASK_INTERRUPTIBLE);
	while (bind_info->is_calling) {
		IPC_DEBUG("[cpu/%d][%s/%d] client begin schedule\n", smp_processor_id(),
				  tsk->comm, tsk->pid);
		schedule();
		IPC_DEBUG("[cpu/%d][%s/%d] client schedule end\n", smp_processor_id(),
				  tsk->comm, tsk->pid);
		if (signal_pending(current)) {
			ret = -EINTR;
			pr_err("[cpu/%d][%s/%d] client has signal, wait server finish\n",
				   smp_processor_id(), tsk->comm, tsk->pid);
			msleep(20);
			set_current_state(TASK_RUNNING);
			/* for next loop, server change the is_calling flags */
			if (!bind_info->is_calling)
				pr_err("server finish\n");
		}
	}
	set_current_state(TASK_RUNNING);

	if (bind_info->is_calling) {
		pr_err("[cpu/%d][%s/%d] server is still calling, but client is waken up\n",
			   smp_processor_id(), tsk->comm, tsk->pid);
		pr_err("[cpu/%d][%s/%d] servertask(%s/%d) is running on cpu %d\n",
			   smp_processor_id(), tsk->comm, tsk->pid, server_task->comm,
			   server_task->pid, task_cpu(server_task));
	}

	fast_ipc_client_exit(bind_info, tsk);

	if (ret == -EINTR)
		return ret;
	ret = fast_ipc_get_client_exit_code(bind_info);

	return ret;
}
EXPORT_SYMBOL_GPL(fast_ipc_do_call);

long fast_ipc_ret_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk)
{
	struct task_struct *client_task;

	if (!bind_info->is_calling) {
		pr_err("confusing bug is_no_calling\n");
		return 0;
	}

	bind_info_lock(bind_info);
	client_task = bind_info->client_task;
	if (!client_task) {
		pr_err("confusing bug no_client\n");
		bind_info_unlock(bind_info);
		return -ESRCH;
	}

	bind_info_unlock(bind_info);

	bind_info->is_calling = false;
	preempt_disable();
	/* memory barrier for preempt */
	smp_mb();
	wake_up_process(client_task);
	preempt_enable();
	IPC_DEBUG("[CPU/%d][%s/%d] client task pid: %d, state: %d\n",
			  smp_processor_id(), tsk->comm, tsk->pid, client_task->pid,
			  client_task->state);

	return 0;
}
EXPORT_SYMBOL_GPL(fast_ipc_ret_call);

long fast_ipc_wait_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk)
{
	long ret = 0;
	sigset_t pending_signals;

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (bind_info->is_calling) {
			/* client send a no reply request to userspace,we must handle it */
			if (bind_info->no_reply) {
				bind_info->no_reply = false;
				fast_ipc_ret_call(bind_info, tsk);
			} else
				break;
		}

		if (bind_info->server_need_exit) {
			ret = -ENODEV;
			break;
		}

		schedule();

		if (signal_pending_state(TASK_INTERRUPTIBLE, tsk)
			&& !bind_info->is_calling) {
			if (fatal_signal_pending(tsk)) {
				pr_err("[CPU/%d][%s/%d] current task has SIGKILL\n",
					   smp_processor_id(), tsk->comm, tsk->pid);
			}

			pending_signals = current->pending.signal;
			ret = -ERESTARTSYS;
			break;
		}
	}

	set_current_state(TASK_RUNNING);
	return ret;
}
EXPORT_SYMBOL_GPL(fast_ipc_wait_call);

static int __init
fast_ipc_init(void)
{
	pr_info("fast ipc init\n");
	return 0;
}

static void __exit
fast_ipc_exit(void)
{
	pr_info("fast ipc exit\n");
}


module_init(fast_ipc_init);
module_exit(fast_ipc_exit);
