/*
 * ZETLAB ZSP - core definitions
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>
#include <string.h>

#include "zsp_core.h"

#if !defined(ZSP_CFG_CALL)
#define ZSP_CFG_CALL
#endif

#define ZSP_CEIL(size) (((size) + 3) & ~3u)

ZSP_CFG_CALL void zsp_set_ptr(struct zsp_ptr *ptr, void *block, uint32_t size)
{
	uintptr_t ptr_addr;
	uintptr_t block_addr;

	ptr_addr = (uintptr_t) ptr;
	block_addr = (uintptr_t) block;

	if (block_addr > ptr_addr) {
		ptr->offset = (uint16_t)(block_addr - ptr_addr);
		ptr->size = size;
	}
}

ZSP_CFG_CALL void *zsp_prepare_writer(struct zsp_writer *w, void *base, uint32_t full_size, uint32_t root_size)
{
	uint32_t ceil_size;

	ceil_size = ZSP_CEIL(root_size);

	if (base && ceil_size <= full_size) {
		memset(base, 0x00, ceil_size);
		w->base = (char *) base;
		w->addr = (uintptr_t) base;
		w->full_size = full_size;
		w->write_size = ceil_size;
		w->root_size = ceil_size;
		return w->base;
	}

	return NULL;
}

ZSP_CFG_CALL void *zsp_write_ptr(struct zsp_writer *w, struct zsp_ptr *ptr, uint32_t size)
{
	uintptr_t addr;
	uint32_t ceil_size;

	addr = (uintptr_t) ptr;
	if (addr >= w->addr) {
		addr -= w->addr;
		ceil_size = ZSP_CEIL(size);
		if (addr < w->full_size && w->write_size + ceil_size <= w->full_size) {
			ptr->offset = (uint16_t)(w->write_size - addr);
			ptr->size = size;

			addr = w->write_size;
			memset(w->base + addr, 0x00, ceil_size);
			w->write_size += ceil_size;
			return w->base + addr;
		}
	}

	return NULL;
}

ZSP_CFG_CALL bool zsp_write_str(struct zsp_writer *w, struct zsp_ptr *ptr, const char *str, uint32_t len)
{
	char *dst;

	dst = zsp_write_ptr(w, ptr, len + 1);
	if (dst) {
		if (str && len > 0)
			memcpy(dst, str, len);
		dst[len] = '\0';
		return true;
	}

	return false;
}

ZSP_CFG_CALL uint32_t zsp_get_writer_size(const struct zsp_writer *w)
{
	return w->write_size;
}

ZSP_CFG_CALL const void *zsp_prepare_reader(struct zsp_reader *r, const void *base, uint32_t full_size, uint32_t root_size)
{
	if (base && root_size <= full_size) {
		r->base = (const char *) base;
		r->addr = (uintptr_t) base;
		r->full_size = full_size;
		return r->base;
	}

	return NULL;
}

ZSP_CFG_CALL const void *zsp_read_ptr(const struct zsp_reader *r, const struct zsp_ptr *ptr)
{
	uintptr_t addr;

	if (ptr->offset >= sizeof(struct zsp_ptr) && ptr->size > 0) {
		addr = (uintptr_t) ptr;
		if (addr >= r->addr) {
			addr = (addr - r->addr) + ptr->offset;
			if (addr + ptr->size <= r->full_size)
				return r->base + addr;
		}
	}

	return NULL;
}

ZSP_CFG_CALL const char *zsp_read_str(const struct zsp_reader *r, const struct zsp_ptr *ptr)
{
	const char *str;

	str = zsp_read_ptr(r, ptr);
	if (str && str[ptr->size - 1] == '\0')
		return str;

	return NULL;
}
