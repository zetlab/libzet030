/*
 * ZETLAB ZSP - protocol specifications
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZETLAB_ZSP_SPEC_H
#define ZETLAB_ZSP_SPEC_H

#include <stdint.h>

#include "zsp_core.h"

#define ZSP_CODE_NOP              0x4F4E /* NO */
#define ZSP_CODE_DEVICE_CONSOLE   0x4344 /* DC */
#define ZSP_CODE_DEVICE_REBOOT    0x5244 /* DR */
#define ZSP_CODE_DEVICE_TIME      0x5444 /* DT */
#define ZSP_CODE_DEVICE_LOG       0x4C44 /* DL */
#define ZSP_CODE_STREAM_CONTROL   0x4353 /* SC */
#define ZSP_CODE_STREAM_DAC       0x4453 /* SD */
#define ZSP_CODE_STREAM_TIME      0x5453 /* ST */
#define ZSP_CODE_STREAM_ZERO      0x5A53 /* SZ */
#define ZSP_CODE_STREAM_FRAME_I32 0x3449 /* I4 */
#define ZSP_CODE_STREAM_FRAME_I24 0x3349 /* I3 */
#define ZSP_CODE_STREAM_FRAME_I16 0x3249 /* I2 */
#define ZSP_CODE_FILE_OPERATION   0x4F46 /* FO */
#define ZSP_CODE_FILE_DATA        0x4446 /* FD */
#define ZSP_CODE_FILE_RESULT      0x5246 /* FR */

#define ZSP_DEVICE_LOG_LEVEL_FATAL 0x20544146 /* FAT  */
#define ZSP_DEVICE_LOG_LEVEL_ERROR 0x21525245 /* ERR! */
#define ZSP_DEVICE_LOG_LEVEL_WARN  0x224E5257 /* WRN" */
#define ZSP_DEVICE_LOG_LEVEL_INFO  0x23464E49 /* INF# */
#define ZSP_DEVICE_LOG_LEVEL_DEBUG 0x24474244 /* DBG$ */

#define ZSP_STREAM_CONTROL_ADC 0x0001
#define ZSP_STREAM_CONTROL_DAC 0x0002

#define ZSP_STREAM_DAC_FLAG_ZERO 0x0001

#define ZSP_FILE_OPERATION_LOAD   0x44414F4C /* LOAD */
#define ZSP_FILE_OPERATION_SAVE   0x45564153 /* SAVE */
#define ZSP_FILE_OPERATION_DELETE 0x544C4544 /* DELT */

#define ZSP_FILE_RESULT_OK            0
#define ZSP_FILE_RESULT_BUSY          1
#define ZSP_FILE_RESULT_NOT_FOUND     2
#define ZSP_FILE_RESULT_IO_ERROR      3
#define ZSP_FILE_RESULT_NOT_SUPPORTED 4
#define ZSP_FILE_RESULT_FORMAT_ERROR  5
#define ZSP_FILE_RESULT_CANCELLED     6

struct zsp_header {
	uint16_t full_size; /* including header and body */
	uint16_t token;     /* request token */
	uint16_t code;      /* type of root block */
	uint16_t root_size; /* size of root block */
};

struct zsp_block_device_console {
	struct zsp_ptr text_str;
};

struct zsp_block_device_time {
	uint64_t utc;
};

struct zsp_block_device_log {
	uint64_t utc;
	uint32_t level;
	struct zsp_ptr text_str;
};

struct zsp_block_stream_control {
	uint32_t control;
};

struct zsp_block_stream_dac {
	uint32_t freq;
	uint32_t channel_count;
	uint32_t frame_code;
	uint32_t fifo_size;
	uint32_t flags;
};

struct zsp_block_stream_time {
	uint64_t utc;
};

struct zsp_block_stream_zero {
	uint32_t counter;
	uint32_t sample_count;
};

struct zsp_block_stream_frame {
	uint32_t counter;
	struct zsp_ptr data_ptr;
};

struct zsp_block_file_operation {
	struct zsp_ptr path_str;
	uint32_t operation;
};

struct zsp_block_file_data {
	uint32_t offset;
	struct zsp_ptr data_ptr;
};

struct zsp_block_file_result {
	struct zsp_ptr path_str;
	int32_t result;
};

union zsp_block_union {
	struct zsp_block_device_console device_console;
	struct zsp_block_device_time device_time;
	struct zsp_block_device_log device_log;
	struct zsp_block_stream_control stream_control;
	struct zsp_block_stream_dac stream_dac;
	struct zsp_block_stream_time stream_time;
	struct zsp_block_stream_zero stream_zero;
	struct zsp_block_stream_frame stream_frame;
	struct zsp_block_file_operation file_operation;
	struct zsp_block_file_data file_data;
	struct zsp_block_file_result file_result;
};

#endif
