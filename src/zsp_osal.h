/*
 * ZETLAB ZSP - OS abstraction layer
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZETLAB_ZSP_OSAL_H
#define ZETLAB_ZSP_OSAL_H

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define ZSP_WINAPI 1
#define _CRT_SECURE_NO_WARNINGS
#else
#define ZSP_POSIX 1
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if ZSP_POSIX

#include <pthread.h>
#include <time.h>

typedef pthread_t osal_thread;
typedef pthread_mutex_t osal_mutex;
typedef pthread_cond_t osal_cond;
typedef void (*osal_thread_callback)(void *arg);

#endif

#if ZSP_WINAPI

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h> // _beginthreadex

typedef HANDLE osal_thread;
typedef CRITICAL_SECTION osal_mutex;
typedef CONDITION_VARIABLE osal_cond;
typedef void (*osal_thread_callback)(void *arg);

#endif

static inline void *osal_malloc(size_t sz)
{
	return malloc(sz);
}

static inline void osal_free(void *ptr)
{
	free(ptr);
}

#if ZSP_POSIX

struct osal_thread_context {
	osal_thread_callback cb;
	void *arg;
};

static inline void *osal_thread_forwarder(void *arg)
{
	struct osal_thread_context *ctx = arg;

	ctx->cb(ctx->arg);
	osal_free(ctx);
	return NULL;
}

static inline int osal_thread_create(osal_thread *t, osal_thread_callback cb, void *arg)
{
	struct osal_thread_context *ctx;
	int r;

	ctx = osal_malloc(sizeof(*ctx));
	if (!ctx) {
		return -1;
	}

	ctx->cb = cb;
	ctx->arg = arg;
	r = pthread_create(t, 0, osal_thread_forwarder, ctx);
	if (r != 0) {
		osal_free(ctx);
		return -1;
	}

	return 0;
}

static inline int osal_thread_join(osal_thread *t)
{
	return pthread_join(*t, NULL);
}

static inline int osal_thread_joined(osal_thread *t)
{
	return pthread_self() == *t;
}

static inline int osal_mutex_create(osal_mutex *m)
{
	return pthread_mutex_init(m, NULL);
}

static inline void osal_mutex_destroy(osal_mutex *m)
{
	(void)pthread_mutex_destroy(m);
}

static inline void osal_mutex_lock(osal_mutex *m)
{
	(void)pthread_mutex_lock(m);
}

static inline int osal_mutex_trylock(osal_mutex *m)
{
	return pthread_mutex_trylock(m);
}

static inline void osal_mutex_unlock(osal_mutex *m)
{
	(void)pthread_mutex_unlock(m);
}

static inline int osal_cond_create(osal_cond *c)
{
	pthread_condattr_t ca;
	int r;

	r = pthread_condattr_init(&ca);
	if (r < 0)
		return r;
	r = pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	if (r < 0)
		return r;
	r = pthread_cond_init(c, &ca);
	if (r < 0)
		return r;
	pthread_condattr_destroy(&ca);
	return 0;
}

static inline void osal_cond_destroy(osal_cond *c)
{
	(void)pthread_cond_destroy(c);
}

static inline void osal_cond_signal(osal_cond *c)
{
	(void)pthread_cond_signal(c);
}

static inline void osal_cond_broadcast(osal_cond *c)
{
	(void)pthread_cond_broadcast(c);
}

static inline void osal_cond_wait(osal_cond *c, osal_mutex *m)
{
	(void)pthread_cond_wait(c, m);
}

static inline int osal_cond_timedwait(osal_cond *c, osal_mutex *m, uint32_t ms)
{
	struct timespec ts;
	
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (ms % 1000) * 1000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}
	return pthread_cond_timedwait(c, m, &ts);
}

static inline uint32_t osal_clock_get_ms(void)
{
	struct timespec ts;
	uint32_t ms;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		ms = (uint32_t)(ts.tv_sec * 1000);
		ms += (uint32_t)(ts.tv_nsec + 500000) / 1000000;
	} else {
		ms = 0;
	}
	return ms;
}

#endif

#if ZSP_WINAPI

struct osal_thread_context {
	osal_thread_callback cb;
	void *arg;
};

static inline DWORD WINAPI osal_thread_forwarder(LPVOID arg)
{
	struct osal_thread_context *ctx = arg;

	ctx->cb(ctx->arg);
	osal_free(ctx);
	return 0;
}

static inline int osal_thread_create(osal_thread *t, osal_thread_callback cb, void *arg)
{
	struct osal_thread_context *ctx;

	ctx = osal_malloc(sizeof(*ctx));
	if (!ctx) {
		*t = NULL;
		return -1;
	}

	ctx->cb = cb;
	ctx->arg = arg;
	*t = (HANDLE)_beginthreadex(NULL, 0, osal_thread_forwarder, ctx, 0, NULL);
	if (*t == NULL) {
		osal_free(ctx);
		return -1;
	}

	return 0;
}

static inline int osal_thread_join(osal_thread *t)
{
	if (WaitForSingleObject(*t, INFINITE) != WAIT_FAILED) {
		CloseHandle(*t);
		return 0;
	}

	return -1;
}

static inline int osal_thread_joined(osal_thread *t)
{
	return GetCurrentThreadId() == GetThreadId(*t);
}

static inline int osal_mutex_create(osal_mutex *m)
{
	InitializeCriticalSection(m);
	return 0;
}

static inline void osal_mutex_destroy(osal_mutex *m)
{
	DeleteCriticalSection(m);
}

static inline void osal_mutex_lock(osal_mutex *m)
{
	EnterCriticalSection(m);
}

static inline int osal_mutex_trylock(osal_mutex *m)
{
	return TryEnterCriticalSection(m) ? 0 : -1;
}

static inline void osal_mutex_unlock(osal_mutex *m)
{
	LeaveCriticalSection(m);
}

static inline int osal_cond_create(osal_cond *c)
{
	InitializeConditionVariable(c);
	return 0;
}

static inline void osal_cond_destroy(osal_cond *c)
{
}

static inline void osal_cond_signal(osal_cond *c)
{
	WakeConditionVariable(c);
}

static inline void osal_cond_broadcast(osal_cond *c)
{
	WakeAllConditionVariable(c);
}

static inline void osal_cond_wait(osal_cond *c, osal_mutex *m)
{
	(void)SleepConditionVariableCS(c, m, INFINITE);
}

static inline int osal_cond_timedwait(osal_cond *c, osal_mutex *m, uint32_t ms)
{
	return (SleepConditionVariableCS(c, m, ms) ? 0 : -1);
}

static inline uint32_t osal_clock_get_ms(void)
{
	return GetTickCount();
}

#endif

#endif
