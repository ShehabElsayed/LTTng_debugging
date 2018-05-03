/*
 * Copyright (C) 2013  Mentor Graphics
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _GNU_SOURCE
/*
 * Do _not_ define _LGPL_SOURCE because we don't want to create a
 * circular dependency loop between this malloc wrapper, liburcu and
 * libc.
 */
#include <lttng/ust-dlfcn.h>
#include <helper.h>
#include <pthread.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_IP_PARAM ip
#include "ust_pthread.h"

static __thread int thread_in_trace;

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	static int (*mutex_lock)(pthread_mutex_t *);
	int retval;

	if (!mutex_lock) {
		mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
		if (!mutex_lock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_lock(mutex);
	}

	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, pthread_mutex_lock_req, mutex,
		LTTNG_UST_CALLER_IP());
	retval = mutex_lock(mutex);
	tracepoint(lttng_ust_pthread, pthread_mutex_lock_acq, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	static int (*mutex_trylock)(pthread_mutex_t *);
	int retval;

	if (!mutex_trylock) {
		mutex_trylock = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		if (!mutex_trylock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_trylock(mutex);
	}

	thread_in_trace = 1;
	retval = mutex_trylock(mutex);
	tracepoint(lttng_ust_pthread, pthread_mutex_trylock, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	static int (*mutex_unlock)(pthread_mutex_t *);
	int retval;

	if (!mutex_unlock) {
		mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
		if (!mutex_unlock) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return mutex_unlock(mutex);
	}

	thread_in_trace = 1;
	retval = mutex_unlock(mutex);
	tracepoint(lttng_ust_pthread, pthread_mutex_unlock, mutex,
		retval, LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

//Shehab-- Add instrumentation for barriers and conditional variables
int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	static int (*barrier_wait)(pthread_barrier_t *);
	int retval;

	if (!barrier_wait) {
		barrier_wait = dlsym(RTLD_NEXT, "pthread_barrier_wait");
		if (!barrier_wait) {
			if (thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return barrier_wait(barrier);
	}

	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, pthread_barrier_reach, barrier,
		LTTNG_UST_CALLER_IP());
	retval = barrier_wait(barrier);
	tracepoint(lttng_ust_pthread, pthread_barrier_leave, barrier, 
		LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex)
{
	static int (*cond_wait)(pthread_cond_t *, pthread_mutex_t *);
	int retval;

	if (!cond_wait) {
		cond_wait = dlsym(RTLD_NEXT, "pthread_cond_wait");
		if (!cond_wait) {
			if (!thread_in_trace) {
				abort();	
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return cond_wait(condition, mutex);
	}
	
	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, pthread_cond_wait_begin, condition, mutex,
		LTTNG_UST_CALLER_IP());
	retval = cond_wait(condition, mutex);
	tracepoint(lttng_ust_pthread, pthread_cond_wait_end, condition, mutex,
		LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_cond_signal(pthread_cond_t *condition)
{
	static int (*cond_signal)(pthread_cond_t *);
	int retval;

	if (!cond_signal) {
		cond_signal = dlsym(RTLD_NEXT, "pthread_cond_signal");
		if (!cond_signal) {
			if (!thread_in_trace) {
				abort();
			}	
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return cond_signal(condition);
	}

	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, pthread_cond_signal_begin, condition,
		LTTNG_UST_CALLER_IP());
	retval = cond_signal(condition);
	tracepoint(lttng_ust_pthread, pthread_cond_signal_end, condition,
		LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

int pthread_cond_broadcast(pthread_cond_t *condition)
{
	static int (*cond_broadcast)(pthread_cond_t *);
	int retval;

	if (!cond_broadcast) {
		cond_broadcast = dlsym(RTLD_NEXT, "pthread_cond_broadcast");
		if (!cond_broadcast) {
			if (!thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize pthread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return cond_broadcast(condition);
	}

	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, pthread_cond_broadcast_begin, condition,
		LTTNG_UST_CALLER_IP());
	retval = cond_broadcast(condition);
	tracepoint(lttng_ust_pthread, pthread_cond_broadcast_end, condition,
		LTTNG_UST_CALLER_IP());
	thread_in_trace = 0;
	return retval;
}

//The structure holds the input to the custom thread starter
struct MY_THREAD_DATA {
	//Pointer to function that was originally called in the benchmark
	void *(*original_function)(void *);
	//Original arguments that were passed to the thread functino in the benchmark
	void *original_args;
};

//The custom thread function.
//Mainly this just inserts the tracepoint to mark thread beginning then calls
//the original thread function.
void *thread_starter(void *args)
{
	struct MY_THREAD_DATA *my_thread_data;
	my_thread_data = (struct MY_THREAD_DATA *) args;
	void *(*original_function)(void *) = my_thread_data->original_function;
	void *original_args = my_thread_data->original_args;

	tracepoint(lttng_ust_pthread, thread_begin, LTTNG_UST_CALLER_IP());
	void *retval = original_function(original_args);

	pthread_exit(retval);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
									 void *(*start_routine) (void *), void *arg)
{
	//Create inputs to be passed to custom thread function
	struct MY_THREAD_DATA *my_thread_data;
	my_thread_data = malloc(sizeof(struct MY_THREAD_DATA));
	my_thread_data->original_function = start_routine;
	my_thread_data->original_args = arg;

	static int (*orig_pthread_create)(pthread_t*, const pthread_attr_t*,
																		void *(*)(void *), void*);
	if (!orig_pthread_create) {
		orig_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
		if (!orig_pthread_create) {
			if (!thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize thread wrapper library.\n");
			return EINVAL;
		}
	}
	if (thread_in_trace) {
		return orig_pthread_create(thread, attr, thread_starter, my_thread_data);
	}

	thread_in_trace = 1;
	int rc = orig_pthread_create(thread, attr, thread_starter, my_thread_data);
	thread_in_trace = 0;

	return rc;
}

void pthread_exit(void *value_ptr)
{
	static void (*orig_pthread_exit)(void *);

	if (!orig_pthread_exit) {
		orig_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
		if (!orig_pthread_exit) {
			if (!thread_in_trace) {
				abort();
			}
			fprintf(stderr, "unable to initialize thread wrapper library.\n");
			//return EINVAL;
		}
	}
	if (thread_in_trace) {
		orig_pthread_exit(value_ptr);
		return;
	}

	thread_in_trace = 1;
	tracepoint(lttng_ust_pthread, thread_end, LTTNG_UST_CALLER_IP());
	orig_pthread_exit(value_ptr);
	thread_in_trace = 0;
}
//Shehab--
