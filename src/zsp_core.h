/*
 * ZETLAB ZSP - core definitions
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZETLAB_ZSP_CORE_H
#define ZETLAB_ZSP_CORE_H

#include <stdbool.h>
#include <stdint.h>

struct zsp_ptr {
	int16_t offset;
	uint16_t size;
};

struct zsp_writer {
	char *base;
	uintptr_t addr;

	uint32_t full_size;

	uint32_t write_size;
	uint32_t root_size;
};

struct zsp_reader {
	const char *base;
	uintptr_t addr;

	uint32_t full_size;
};

#ifdef __cplusplus
extern "C" {
#endif

void zsp_set_ptr(struct zsp_ptr *ptr, void *block, uint32_t size);

void *zsp_prepare_writer(struct zsp_writer *w, void *base, uint32_t full_size, uint32_t root_size);

void *zsp_write_ptr(struct zsp_writer *w, struct zsp_ptr *ptr, uint32_t size);
bool zsp_write_str(struct zsp_writer *w, struct zsp_ptr *ptr, const char *str, uint32_t len);

uint32_t zsp_get_writer_size(const struct zsp_writer *w);

const void *zsp_prepare_reader(struct zsp_reader *r, const void *base, uint32_t full_size, uint32_t root_size);

const void *zsp_read_ptr(const struct zsp_reader *r, const struct zsp_ptr *ptr);
const char *zsp_read_str(const struct zsp_reader *r, const struct zsp_ptr *ptr);

#ifdef __cplusplus
}
#endif

#endif
