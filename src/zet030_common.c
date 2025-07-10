/*
 * ZETLAB ZET 030 device library
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#include "zet030.h"
#include "zet030_common.h"

#include "zsp_core.h"

#include <time.h>

/* find non-zero token not matching token used by stream, file, console, or logging */
static uint16_t zet030_generate_next_token(struct zet030_device *d)
{
	uint16_t tok;

	tok = d->next_token + 1;
	while (tok == 0 ||
			tok == d->stream_token ||
			tok == d->file_token ||
			tok == d->console_token ||
			tok == d->logging.token)
	{
		tok++;
	}

	d->next_token = tok;
	return tok;
}

enum zet030_state zet030_get_state(struct zet030_device *d)
{
	enum zet030_state state;

	osal_mutex_lock(&d->state_lock);
	state = d->state;
	osal_mutex_unlock(&d->state_lock);

	return state;
}

void zet030_set_state(struct zet030_device *d, enum zet030_state state)
{
	osal_mutex_lock(&d->state_lock);
	if (d->state < state)
		d->state = state;
	osal_mutex_unlock(&d->state_lock);
}

static void zet030_stop_thread(struct zet030_device *d)
{
	switch (zet030_get_state(d)) {
	case ZET030_STATE_CONNECTING:
	case ZET030_STATE_CONNECTED:
		zet030_set_state(d, ZET030_STATE_CLOSING);
		break;
	case ZET030_STATE_CLOSING:
		break;
	case ZET030_STATE_CLOSED:
		return;
	}

	d->backend.wakeup(d);
	osal_thread_join(&d->thread);
	zet030_set_state(d, ZET030_STATE_CLOSED);
}

static int zet030_lock_api_call(struct zet030_device *d, int check_stream_stopped)
{
	int r;

	r = zet030_check_open(d);
	if (r != 0)
		return r;

	osal_mutex_lock(&d->api_lock);

	if (d->api_state != ZET030_API_STATE_IDLE) {
		osal_mutex_unlock(&d->api_lock);
		return ZET030_ERROR_BUSY;
	}

	if (check_stream_stopped && d->stream_token != 0) {
		osal_mutex_unlock(&d->api_lock);
		return ZET030_ERROR_STARTED;
	}

	return 0;
}

static void zet030_unlock_api_call(struct zet030_device *d)
{
	d->api_request = ZET030_API_REQUEST_NOP;
	if (d->api_state != ZET030_API_STATE_CANCELLED)
		d->api_state = ZET030_API_STATE_IDLE;

	osal_mutex_unlock(&d->api_lock);
}

static int zet030_call_api(struct zet030_device *d, enum zet030_api_request request, uint32_t wait_ms)
{
	int r;

	r = 0;
	d->api_request = request;
	d->api_state = ZET030_API_STATE_REQUESTED;

	d->backend.wakeup(d);

	if (wait_ms == 0) {
		osal_mutex_unlock(&d->api_lock);
		return 0;
	}

	while (d->api_state != ZET030_API_STATE_COMPLETED) {
		if (osal_cond_timedwait(&d->api_completed, &d->api_lock, wait_ms) != 0) {
			d->api_state = ZET030_API_STATE_CANCELLED;
			zet030_unlock_api_call(d);

			zet030_stop_thread(d);
			return ZET030_ERROR_TIMEOUT;
		}
	}
	r = d->api_result;

	zet030_unlock_api_call(d);
	return r;
}

enum zet030_api_state zet030_lock_api_work(struct zet030_device *d)
{
	osal_mutex_lock(&d->api_lock);

	if (d->api_state == ZET030_API_STATE_REQUESTED) {
		d->api_state = ZET030_API_STATE_PROCESSING;
		return ZET030_API_STATE_REQUESTED;
	}

	if (d->api_state == ZET030_API_STATE_PROCESSING)
		return ZET030_API_STATE_PROCESSING;

	osal_mutex_unlock(&d->api_lock);
	return ZET030_API_STATE_IDLE;
}

void zet030_unlock_api_work(struct zet030_device *d, int result)
{
	if (result != ZET030_ERROR_BUSY) {
		d->api_state = ZET030_API_STATE_COMPLETED;
		d->api_request = ZET030_API_REQUEST_NOP;
		d->api_result = result;
		osal_cond_signal(&d->api_completed);
	}

	osal_mutex_unlock(&d->api_lock);
}

union zsp_block_union *zet030_prepare_cmd(struct zet030_device *d, struct zsp_writer *w, uint32_t root_size)
{
	return zsp_prepare_writer(w,
			d->tx_cmd.buf + sizeof(struct zsp_header),
			ZET030_TX_BUFSIZE - sizeof(struct zsp_header),
			root_size);
}

static void zet030_finish_cmd(struct zet030_device *d, const struct zsp_writer *w, uint16_t token, uint16_t code)
{
	struct zsp_header *h;

	h = (struct zsp_header *)d->tx_cmd.buf;
	h->full_size = (uint16_t)(sizeof(struct zsp_header) + w->write_size);
	h->token = token;
	h->code = code;
	h->root_size = w->root_size;

	d->tx_cmd.pos = 0;
	d->tx_cmd.avail = h->full_size;
}

void zet030_build_device_time(struct zet030_device *d)
{
	struct zsp_writer w;
	union zsp_block_union *tx;
	time_t utc;

	time(&utc);

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->device_time));
	tx->device_time.utc = utc;
	zet030_finish_cmd(d, &w, zet030_generate_next_token(d), ZSP_CODE_DEVICE_TIME);
}

static void zet030_build_stream_control(struct zet030_device *d, uint32_t control)
{
	struct zsp_writer w;
	union zsp_block_union *tx;

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->stream_control));
	tx->stream_control.control = control;
	zet030_finish_cmd(d, &w, d->stream_token, ZSP_CODE_STREAM_CONTROL);
}

static int zet030_build_device_console(struct zet030_device *d, const char *text)
{
	struct zsp_writer w;
	union zsp_block_union *tx;

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->device_console));
	if (!zsp_write_str(&w, &tx->device_console.text_str, text, (uint32_t)strlen(text)))
		return -1;
	zet030_finish_cmd(d, &w, d->console_token, ZSP_CODE_DEVICE_CONSOLE);
	return 0;
}

static void zet030_build_device_log(struct zet030_device *d, enum zet030_log_level level)
{
	struct zsp_writer w;
	union zsp_block_union *tx;

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->device_log));
	tx->device_log.utc = 0;
	tx->device_log.level = level;
	zet030_finish_cmd(d, &w, d->logging.token, ZSP_CODE_DEVICE_LOG);
}

static int zet030_build_file_operation(struct zet030_device *d, const char *path, uint32_t op)
{
	struct zsp_writer w;
	union zsp_block_union *tx;

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->file_operation));
	if (!zsp_write_str(&w, &tx->file_operation.path_str, path, (uint32_t)strlen(path)))
		return -1;
	tx->file_operation.operation = op;
	zet030_finish_cmd(d, &w, d->file_token, ZSP_CODE_FILE_OPERATION);
	return 0;
}

static int zet030_build_file_data(struct zet030_device *d, uint32_t offset, const void *data, uint32_t size)
{
	struct zsp_writer w;
	union zsp_block_union *tx;
	void *dst;

	tx = zet030_prepare_cmd(d, &w, sizeof(tx->file_data));
	tx->file_data.offset = offset;
	if (data && size > 0) {
		dst = zsp_write_ptr(&w, &tx->file_data.data_ptr, size);
		if (!dst)
			return -1;
		memcpy(dst, data, size);
	}
	zet030_finish_cmd(d, &w, d->file_token, ZSP_CODE_FILE_DATA);
	return 0;
}

static void zet030_run_thread(void *arg)
{
	struct zet030_device *d = arg;

	d->backend.run(d);
}

void zet030_build_tx(struct zet030_device *d)
{
	enum zet030_api_state state;
	union zet030_api_context *ctx;
	int result;
	int r;

	state = zet030_lock_api_work(d);

	result = ZET030_ERROR_BUSY;

	if (state == ZET030_API_STATE_REQUESTED) {
		ctx = &d->api_context;

		switch (d->api_request) {
		case ZET030_API_REQUEST_START:
			if (d->stream_token != 0) {
				/* already started */
				result = ZET030_ERROR_STARTED;
				break;
			}
			d->stream_token = zet030_generate_next_token(d);
			d->stream_cb = ctx->start.cb;
			d->stream_cb_arg = ctx->start.cb_arg;
			d->stream_time.utc = 0;
			d->stream_time.counter = 0xFFFFFFFF;

			zet030_build_stream_control(d, 1);
			break;

		case ZET030_API_REQUEST_STOP:
			if (d->stream_token == 0) {
				/* already stopped */
				result = 0;
				break;
			}

			d->stream_cb = NULL;
			zet030_build_stream_control(d, 0);
			break;

		case ZET030_API_REQUEST_LOAD:
			d->file_token = zet030_generate_next_token(d);
			d->file_offset = 0;

			if (zet030_build_file_operation(d, ctx->load.path, ZSP_FILE_OPERATION_LOAD) != 0) {
				result = ZET030_ERROR_OUT_OF_MEMORY;
				break;
			}
			break;

		case ZET030_API_REQUEST_SAVE:
			d->file_token = zet030_generate_next_token(d);
			d->file_offset = 0;

			if (zet030_build_file_operation(d, ctx->save.path, ZSP_FILE_OPERATION_SAVE) != 0) {
				result = ZET030_ERROR_OUT_OF_MEMORY;
				return;
			}
			break;

		case ZET030_API_REQUEST_DELETE:
			d->file_token = zet030_generate_next_token(d);
			d->file_offset = 0;

			if (zet030_build_file_operation(d, ctx->delt.path, ZSP_FILE_OPERATION_DELETE) != 0) {
				result = ZET030_ERROR_OUT_OF_MEMORY;
				return;
			}
			break;

		case ZET030_API_REQUEST_TALK:
			d->console_token = zet030_generate_next_token(d);

			if (zet030_build_device_console(d, ctx->talk.text) != 0) {
				result = ZET030_ERROR_OUT_OF_MEMORY;
				break;
			}
			break;

		case ZET030_API_REQUEST_SUBSCRIBE:
			d->logging.token = zet030_generate_next_token(d);

			if (ctx->subscribe.max_level != ZET030_LOG_LEVEL_OFF && ctx->subscribe.cb) {
				d->logging.max_level = (uint32_t)ctx->subscribe.max_level;
				d->logging.cb = ctx->subscribe.cb;
				d->logging.cb_arg = ctx->subscribe.cb_arg;
			} else {
				d->logging.max_level = ZET030_LOG_LEVEL_OFF;
				d->logging.cb = NULL;
				d->logging.cb_arg = NULL;
			}
			zet030_build_device_log(d, ctx->subscribe.max_level);

			if (d->logging.max_level == ZET030_LOG_LEVEL_OFF) {
				// reset and unlock api
				d->logging.token = 0;
				result = 0;
			}
			break;
		}

		zet030_unlock_api_work(d, result);
		return;
	}

	if (state == ZET030_API_STATE_PROCESSING) {
		ctx = &d->api_context;

		switch (d->api_request) {
		case ZET030_API_REQUEST_SAVE:
			if (ctx->save.eof)
				break;

			r = ctx->save.cb(d, ctx->save.cb_arg, d->file_offset, ctx->save.buf, ZET030_FILE_BUFSIZE);
			if (r <= 0 || r > ZET030_FILE_BUFSIZE) {
				/* send empty packet and wait for file result */
				r = 0;
				ctx->save.eof = 1;
			}

			if (zet030_build_file_data(d, d->file_offset, ctx->save.buf, (uint32_t)r) != 0) {
				result = ZET030_ERROR_OUT_OF_MEMORY;
				break;
			}
			d->file_offset += r;
			break;
		}

		zet030_unlock_api_work(d, result);
		return;
	}
}

void zet030_parse_rx(struct zet030_device *d, const struct zsp_header *h, const void *body)
{
	struct zsp_reader r;
	const union zsp_block_union *rx;
	union zet030_api_context *ctx;
	const char *str;
	const int32_t *data_i32;
	const uint8_t *data_u8;
	uint8_t *dst_u8;
	int size;
	int result;

	rx = zsp_prepare_reader(&r, body, h->full_size - sizeof(struct zsp_header), h->root_size);
	if (!rx)
		return;

	ctx = &d->api_context;

	if (d->stream_token && d->stream_token == h->token) {
		switch (h->code) {
		case ZSP_CODE_STREAM_FRAME_I32:
			if (h->root_size < sizeof(rx->stream_frame))
				return;
			if (d->stream_time.counter == rx->stream_frame.counter)
				return;
			d->stream_time.counter = rx->stream_frame.counter;

			if (d->stream_cb) {
				data_i32 = zsp_read_ptr(&r, &rx->stream_frame.data_ptr);
				size = rx->stream_frame.data_ptr.size / sizeof(int32_t);
				d->stream_cb(d, d->stream_cb_arg, data_i32, size, &d->stream_time);
				return;
			}
			return;

		case ZSP_CODE_STREAM_FRAME_I24:
			if (h->root_size < sizeof(rx->stream_frame))
				return;
			if (d->stream_time.counter == rx->stream_frame.counter)
				return;
			d->stream_time.counter = rx->stream_frame.counter;

			if (d->stream_cb) {
				dst_u8 = (uint8_t *)d->stream_space;
				data_u8 = zsp_read_ptr(&r, &rx->stream_frame.data_ptr);
				size = rx->stream_frame.data_ptr.size / 3;
				for (int i = 0; i < size; i++) {
					dst_u8[0] = 0x00;
					dst_u8[1] = data_u8[0];
					dst_u8[2] = data_u8[1];
					dst_u8[3] = data_u8[2];
					dst_u8 += sizeof(int32_t);
					data_u8 += 3;
				}
				data_i32 = d->stream_space;
				d->stream_cb(d, d->stream_cb_arg, data_i32, size, &d->stream_time);
				return;
			}
			return;

		case ZSP_CODE_STREAM_FRAME_I16:
			if (h->root_size < sizeof(rx->stream_frame))
				return;
			if (d->stream_time.counter == rx->stream_frame.counter)
				return;
			d->stream_time.counter = rx->stream_frame.counter;

			if (d->stream_cb) {
				data_u8 = zsp_read_ptr(&r, &rx->stream_frame.data_ptr);
				size = rx->stream_frame.data_ptr.size / sizeof(int16_t);
				memset(d->stream_space, 0x00, size * sizeof(int32_t));
				for (int i = 0; i < size; i++) {
					memcpy(&d->stream_space[i], data_u8, sizeof(int16_t));
					data_u8 += sizeof(int16_t);
				}
				data_i32 = d->stream_space;
				d->stream_cb(d, d->stream_cb_arg, data_i32, size, &d->stream_time);
				return;
			}
			return;

		case ZSP_CODE_STREAM_TIME:
			if (h->root_size < sizeof(rx->stream_time))
				return;

			d->stream_time.utc = rx->stream_time.utc;
			return;

		case ZSP_CODE_STREAM_CONTROL:
			if (h->root_size < sizeof(rx->stream_control))
				return;

			if (rx->stream_control.control == 0) {
				d->stream_token = 0;
				d->stream_cb = NULL;
			}

			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				result = ZET030_ERROR_OTHER;
				switch (d->api_request) {
				case ZET030_API_REQUEST_START:
					if (rx->stream_control.control != 0)
						result = 0;
					break;
				case ZET030_API_REQUEST_STOP:
					if (rx->stream_control.control == 0)
						result = 0;
					break;
				}
				if (result != 0) {
					d->stream_token = 0;
					d->stream_cb = NULL;
				}
				zet030_unlock_api_work(d, 0);
			}
			return;
		}
	}

	if (d->console_token && d->console_token == h->token) {
		switch (h->code) {
		case ZSP_CODE_DEVICE_CONSOLE:
			if (h->root_size < sizeof(rx->device_console))
				return;

			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				if (ctx->talk.response && ctx->talk.response_size > 0) {
					str = zsp_read_str(&r, &rx->device_console.text_str);
					size = rx->device_console.text_str.size;
					if (size > ctx->talk.response_size)
						size = ctx->talk.response_size;
					if (size > 1) {
						memcpy(ctx->talk.response, str, size - 1);
						ctx->talk.response[size - 1] = '\0';
					} else {
						ctx->talk.response[0] = '\0';
					}
				}
				d->console_token = 0;
				zet030_unlock_api_work(d, 0);
			}
			return;

		case ZSP_CODE_NOP: /* not supported */
			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				d->console_token = 0;
				zet030_unlock_api_work(d, ZET030_ERROR_NOT_SUPPORTED);
				return;
			}
			return;
		}
	}

	if (d->logging.token && d->logging.token == h->token) {
		switch (h->code) {
		case ZSP_CODE_DEVICE_LOG:
			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				if (h->root_size < sizeof(rx->device_log)) {
					d->logging.token = 0;
					zet030_unlock_api_work(d, ZET030_ERROR_NOT_SUPPORTED);
				} if (rx->device_log.level != d->logging.max_level) {
					d->logging.token = 0;
					zet030_unlock_api_work(d, ZET030_ERROR_OTHER);
				} else {
					zet030_unlock_api_work(d, 0);
				}
				return;
			}

			if (h->root_size < sizeof(rx->device_log))
				return;

			if (rx->device_log.level > d->logging.max_level)
				return;

			str = zsp_read_str(&r, &rx->device_log.text_str);
			if (!str)
				return;

			if (d->logging.cb)
				d->logging.cb(d, d->logging.cb_arg, rx->device_log.utc, rx->device_log.level, str);
			return;

		case ZSP_CODE_NOP: /* not supported */
			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				d->console_token = 0;
				zet030_unlock_api_work(d, ZET030_ERROR_NOT_SUPPORTED);
				return;
			}
			return;
		}
	}

	if (d->file_token && d->file_token == h->token) {
		switch (h->code) {
		case ZSP_CODE_FILE_DATA:
			if (h->root_size < sizeof(rx->file_data))
				return;

			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				result = ZET030_ERROR_BUSY;
				if (d->api_request == ZET030_API_REQUEST_LOAD && ctx->load.cb) {
					data_u8 = zsp_read_ptr(&r, &rx->file_data.data_ptr);
					size = rx->file_data.data_ptr.size;
					if (ctx->load.cb(d, ctx->load.cb_arg, d->file_offset, data_u8, size) < 0) {
						d->file_token = 0;
						result = ZET030_ERROR_OTHER;
					}
				}
				zet030_unlock_api_work(d, result);
			}

			d->file_offset += rx->file_data.data_ptr.size;
			return;

		case ZSP_CODE_FILE_RESULT:
			if (h->root_size < sizeof(rx->file_result))
				return;

			if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
				result = ZET030_ERROR_BUSY;

				switch (d->api_request) {
				case ZET030_API_REQUEST_LOAD:
				case ZET030_API_REQUEST_SAVE:
				case ZET030_API_REQUEST_DELETE:
					d->file_token = 0;
					switch (rx->file_result.result) {
					case ZSP_FILE_RESULT_OK:
						result = 0;
						break;
					case ZSP_FILE_RESULT_NOT_FOUND:
						result = ZET030_ERROR_FILE_NOT_FOUND;
						break;
					case ZSP_FILE_RESULT_FORMAT_ERROR:
						result = ZET030_ERROR_INVALID_FORMAT;
						break;
					case ZSP_FILE_RESULT_NOT_SUPPORTED:
						result = ZET030_ERROR_NOT_SUPPORTED;
						break;
					default:
						result = ZET030_ERROR_OTHER;
						break;
					}
				}
				zet030_unlock_api_work(d, result);
			}
			return;
		}
	}
}

int zet030_init_device(struct zet030_device *d, uint32_t wait_ms)
{
	/* this mutex will be unlocked to request device thread to stop */
	osal_mutex_create(&d->state_lock);
	d->state = ZET030_STATE_CONNECTING;

	osal_mutex_create(&d->api_lock);
	d->api_state = ZET030_API_STATE_IDLE;
	d->api_request = ZET030_API_REQUEST_NOP;
	osal_cond_create(&d->api_completed);

	zet030_lock_api_call(d, 0);

	osal_thread_create(&d->thread, zet030_run_thread, d);

	return zet030_call_api(d, ZET030_API_REQUEST_CONNECT, wait_ms);
}

int zet030_close(struct zet030_device *d)
{
	if (!d)
		return ZET030_ERROR_INVALID_PARAMETER;

	osal_mutex_lock(&d->api_lock);
	d->api_state = ZET030_API_STATE_CANCELLED;
	osal_mutex_unlock(&d->api_lock);

	zet030_stop_thread(d);

	osal_cond_destroy(&d->api_completed);
	osal_mutex_destroy(&d->api_lock);

	osal_mutex_destroy(&d->state_lock);

	d->backend.free(d);
	return 0;
}

int zet030_check_open(struct zet030_device *d)
{
	if (!d)
		return ZET030_ERROR_INVALID_PARAMETER;

	switch (zet030_get_state(d)) {
	case ZET030_STATE_CONNECTING:
		return ZET030_ERROR_BUSY;
	case ZET030_STATE_CLOSED:
	case ZET030_STATE_CLOSING:
		return ZET030_ERROR_CLOSED;
	default:
		break;
	}

	return 0;
}

int zet030_start(struct zet030_device *d, zet030_stream_callback cb, void *arg)
{
	int r;

	if (!cb)
		return ZET030_ERROR_INVALID_PARAMETER;

	r = zet030_lock_api_call(d, 1);
	if (r == 0) {
		d->api_context.start.cb = cb;
		d->api_context.start.cb_arg = arg;
		r = zet030_call_api(d, ZET030_API_REQUEST_START, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_stop(struct zet030_device *d)
{
	int r;

	r = zet030_lock_api_call(d, 0);
	if (r == 0) {
		r = zet030_call_api(d, ZET030_API_REQUEST_STOP, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_load(struct zet030_device *d, const char *path, zet030_load_callback cb, void *arg)
{
	int r;

	if (!path || !cb)
		return ZET030_ERROR_INVALID_PARAMETER;

	r = zet030_lock_api_call(d, 1);
	if (r == 0) {
		d->api_context.load.path = path;
		d->api_context.load.cb = cb;
		d->api_context.load.cb_arg = arg;
		r = zet030_call_api(d, ZET030_API_REQUEST_LOAD, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_save(struct zet030_device *d, const char *path, zet030_save_callback cb, void *arg)
{
	int r;

	if (!path || !cb)
		return ZET030_ERROR_INVALID_PARAMETER;

	r = zet030_lock_api_call(d, 1);
	if (r == 0) {
		d->api_context.save.path = path;
		d->api_context.save.cb = cb;
		d->api_context.save.cb_arg = arg;
		d->api_context.save.eof = 0;
		r = zet030_call_api(d, ZET030_API_REQUEST_SAVE, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_delete(struct zet030_device *d, const char *path)
{
	int r;

	if (!path)
		return ZET030_ERROR_INVALID_PARAMETER;

	r = zet030_lock_api_call(d, 1);
	if (r == 0) {
		d->api_context.delt.path = path;
		r = zet030_call_api(d, ZET030_API_REQUEST_DELETE, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_talk(struct zet030_device *d, const char *text, char *response, int response_size)
{
	int r;

	if (!text)
		return ZET030_ERROR_INVALID_PARAMETER;

	r = zet030_lock_api_call(d, 0);
	if (r == 0) {
		d->api_context.talk.text = text;
		d->api_context.talk.response = response;
		d->api_context.talk.response_size = response_size;
		r = zet030_call_api(d, ZET030_API_REQUEST_TALK, ZET030_API_TIMEOUT);
	}

	return r;
}

int zet030_subscribe(struct zet030_device *d, enum zet030_log_level max_level, zet030_log_callback cb, void *arg)
{
	int r;

	r = zet030_lock_api_call(d, 0);
	if (r == 0) {
		d->api_context.subscribe.max_level = max_level;
		d->api_context.subscribe.cb = cb;
		d->api_context.subscribe.cb_arg = arg;
		r = zet030_call_api(d, ZET030_API_REQUEST_SUBSCRIBE, ZET030_API_TIMEOUT);
	}

	return r;
}
