/*
 * SPDX-License-Identifier: MIT
 */

#ifndef ZETLAB_ZET030_COMMON_H
#define ZETLAB_ZET030_COMMON_H

#include "zsp_osal.h"
#include "zsp_spec.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zet030.h"

#define ZET030_DEFAULT_PORT 1832

#define ZET030_TX_BUFSIZE 2048
#define ZET030_RX_BUFSIZE 4096

#define ZET030_FILE_BUFSIZE 512

#define ZET030_TX_TIMEOUT 2000
#define ZET030_RX_TIMEOUT 1000
#define ZET030_API_TIMEOUT 5000

enum zet030_state {
	ZET030_STATE_CONNECTING,
	ZET030_STATE_CONNECTED,
	ZET030_STATE_CLOSING,
	ZET030_STATE_CLOSED,
};

enum zet030_api_state {
	ZET030_API_STATE_IDLE,
	ZET030_API_STATE_REQUESTED,
	ZET030_API_STATE_PROCESSING,
	ZET030_API_STATE_COMPLETED,
	ZET030_API_STATE_CANCELLED,
};

enum zet030_api_request {
	ZET030_API_REQUEST_NOP,
	ZET030_API_REQUEST_CONNECT,
	ZET030_API_REQUEST_START,
	ZET030_API_REQUEST_STOP,
	ZET030_API_REQUEST_LOAD,
	ZET030_API_REQUEST_SAVE,
	ZET030_API_REQUEST_DELETE,
	ZET030_API_REQUEST_TALK,
	ZET030_API_REQUEST_SUBSCRIBE,
};

struct zet030_api_connect {
	zet030_connect_callback cb;
	void *cb_arg;
};

struct zet030_api_start {
	zet030_stream_callback cb;
	void *cb_arg;
};

struct zet030_api_load {
	const char *path;
	zet030_load_callback cb;
	void *cb_arg;
};

struct zet030_api_save {
	const char *path;
	zet030_save_callback cb;
	void *cb_arg;

	uint8_t buf[ZET030_FILE_BUFSIZE];
	int eof;
};

struct zet030_api_delete {
	const char *path;
};

struct zet030_api_talk {
	uint16_t token;
	const char *text;
	char *response;
	int response_size;
};

struct zet030_api_subscribe {
	enum zet030_log_level max_level;
	zet030_log_callback cb;
	void *cb_arg;
};

union zet030_api_context {
	struct zet030_api_connect connect;
	struct zet030_api_start start;
	struct zet030_api_load load;
	struct zet030_api_save save;
	struct zet030_api_delete delt;
	struct zet030_api_talk talk;
	struct zet030_api_subscribe subscribe;
};

struct zet030_tx {
	struct zet030_device *device;

	uint8_t buf[ZET030_TX_BUFSIZE];
	int pos;
	int avail;
};

struct zet030_rx {
	struct zet030_device *device;

	uint8_t buf[ZET030_RX_BUFSIZE];
	int pos;
};

struct zet030_backend {
	void (*run)(struct zet030_device *d);
	void (*wakeup)(struct zet030_device *d);
	void (*free)(struct zet030_device *d);
};

struct zet030_logging {
	uint32_t max_level;
	zet030_log_callback cb;
	void *cb_arg;

	uint16_t token;
};

struct zet030_device {
	struct zet030_backend backend;

	osal_mutex state_lock;
	enum zet030_state state;

	osal_mutex api_lock;
	osal_cond api_completed;
	enum zet030_api_state api_state;
	enum zet030_api_request api_request;
	union zet030_api_context api_context;
	int api_result;

	osal_thread thread;

	struct zet030_tx tx_cmd;
	struct zet030_rx rx_rsp;
	struct zet030_rx rx_adc;

	uint16_t next_token;

	uint16_t stream_token;
	int32_t stream_space[ZET030_RX_BUFSIZE / sizeof(int32_t)];
	zet030_stream_callback stream_cb;
	void *stream_cb_arg;
	struct zet030_stream_time stream_time;

	uint16_t file_token;
	uint32_t file_offset;

	uint16_t console_token;

	struct zet030_logging logging;
};

enum zet030_state zet030_get_state(struct zet030_device *d);
void zet030_set_state(struct zet030_device *d, enum zet030_state state);
void zet030_parse_rx(struct zet030_device *d, const struct zsp_header *h, const void *body);

enum zet030_api_state zet030_lock_api_work(struct zet030_device *d);
void zet030_unlock_api_work(struct zet030_device *d, int result);

void zet030_build_device_time(struct zet030_device *d);
void zet030_build_tx(struct zet030_device *d);

int zet030_init_device(struct zet030_device *d, uint32_t wait_ms);

#endif
