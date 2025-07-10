/*
 * ZETLAB ZET 030 device library
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#include "zet030.h"
#include "zet030_common.h"

#include <libusb.h>

#define ZET030_VID   0x2FFD
#define ZET030_P_PID 0x001E
#define ZET030_I_PID 0x001F

#define ZET030_CMD_BUFSIZE 1024
#define ZET030_RSP_BUFSIZE 1024

#define ZET030_ADC_BUFCOUNT 2
#define ZET030_ADC_BUFSIZE (64*1024)

#define ZET030_FLUSH_TIMEOUT 200

#define ZET030_CONTROL_REQ_RESET 0xFF

// callback used internally by zet030_scan(), zet030_open_path(), and zet030_open_serial()
typedef int (*zet030_usb_enumerate_callback)(void *arg, struct libusb_device *dev, const struct libusb_device_descriptor *desc, const char *path);

struct zet030_usb {
	struct zet030_device device;

	struct libusb_transfer *tr_wakeup;

	struct libusb_context *ctx;
	struct libusb_device_handle *handle;
	struct libusb_device *dev;
	uint32_t serial;
	int interface_index;

	uint8_t ep_cmd;
	uint8_t ep_rsp;
	uint8_t ep_adc;
	uint8_t ep_dac;

	struct libusb_transfer *tr_cmd;
	struct libusb_transfer *tr_rsp;
	struct libusb_transfer *tr_adc[ZET030_ADC_BUFCOUNT];

	uint8_t trbuf_rsp[ZET030_RSP_BUFSIZE];
	uint8_t trbuf_adc[ZET030_ADC_BUFCOUNT][ZET030_ADC_BUFSIZE];
};

// enumeration context for zet030_scan()
struct zet030_scan_info {
	zet030_scan_callback cb;
	void *arg;
};

// enumeration context for zet030_open_path() and zet030_open_serial()
struct zet030_open_info {
	const char *path;
	uint32_t serial;
	struct libusb_device_handle *handle;
};

static int zet030_usb_receive_rx(struct zet030_rx *rx, const uint8_t *buffer, int actual_length)
{
	const struct zsp_header *h;
	const uint8_t *rx_p;
	int rx_size;

	while (actual_length > 0) {
		rx_size = ZET030_RX_BUFSIZE - rx->pos;
		if (rx_size > actual_length)
			rx_size = actual_length;
		memcpy(&rx->buf[rx->pos], buffer, rx_size);
		rx->pos += rx_size;
		buffer += rx_size;
		actual_length -= rx_size;

		rx_p = rx->buf;
		rx_size = rx->pos;
		while (rx_size >= sizeof(*h)) {
			h = (const struct zsp_header *)rx_p;
			if (h->full_size < sizeof(*h) || h->full_size > ZET030_RX_BUFSIZE) {
				// packet sync lost
				rx->pos = 0;
				return -1;
			}
			if (rx_size < h->full_size)
				break;

			zet030_parse_rx(rx->device, h, rx_p + sizeof(*h));

			rx_p += h->full_size;
			rx_size -= h->full_size;
		}

		if (rx_size > 0)
			memmove(rx->buf, rx_p, rx_size);
		rx->pos = rx_size;
	}

	return 0;
}

static void LIBUSB_CALL zet030_usb_handle_wakeup_transfer(struct libusb_transfer *tr)
{
	tr->user_data = NULL;
}

static void LIBUSB_CALL zet030_usb_handle_tx_cmd_transfer(struct libusb_transfer *tr)
{
	struct zet030_tx *tx;
	struct zet030_device *d;

	tx = tr->user_data;
	if (!tx)
		return;
	tr->user_data = NULL;

	d = tx->device;
	if (zet030_get_state(d) >= ZET030_STATE_CLOSING)
		return;

	if (tr->status == LIBUSB_TRANSFER_COMPLETED) {
		tx->avail = 0;
		tx->pos = 0;
	} else {
		zet030_set_state(d, ZET030_STATE_CLOSING);
	}
}

static void LIBUSB_CALL zet030_usb_handle_rx_transfer(struct libusb_transfer *tr)
{
	struct zet030_rx *rx;
	struct zet030_device *d;

	rx = tr->user_data;
	if (!rx)
		return;
	tr->user_data = NULL;

	d = rx->device;
	if (zet030_get_state(d) >= ZET030_STATE_CLOSING)
		return;

	switch (tr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
	case LIBUSB_TRANSFER_TIMED_OUT:
		if (zet030_usb_receive_rx(rx, tr->buffer, tr->actual_length) == 0) {
			if (libusb_submit_transfer(tr) == 0)
				tr->user_data = rx;
		}
		break;
	case LIBUSB_TRANSFER_CANCELLED:
	case LIBUSB_TRANSFER_NO_DEVICE:
		break;
	default:
		if (libusb_submit_transfer(tr) == 0)
			tr->user_data = rx;
		break;
	}

	if (!tr->user_data)
		zet030_set_state(d, ZET030_STATE_CLOSING);
}

static int zet030_usb_check_transfer_stopped(struct zet030_usb *usb)
{
	int i;

	if (usb->tr_wakeup->user_data)
		return -1;
	if (usb->tr_cmd->user_data)
		return -1;
	if (usb->tr_rsp->user_data)
		return -1;
	for (i = 0; i < ZET030_ADC_BUFCOUNT; i++) {
		if (usb->tr_adc[i]->user_data)
			return -1;
	}

	return 0;
}

static void zet030_usb_run(struct zet030_device *d)
{
	struct zet030_usb *usb = (struct zet030_usb *)d;
	int i;
	int r;

	r = ZET030_ERROR_CLOSED;
	if (zet030_lock_api_work(d) == ZET030_API_STATE_REQUESTED) {
		if (d->api_request == ZET030_API_REQUEST_CONNECT)
			r = ZET030_ERROR_BUSY;
		zet030_unlock_api_work(d, r);
	}
	if (r != ZET030_ERROR_BUSY) {
		zet030_set_state(d, ZET030_STATE_CLOSED);
		return;
	}

	/* reset and flush endpoints */
	libusb_control_transfer(usb->handle,
			LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_INTERFACE,
			ZET030_CONTROL_REQ_RESET,
			0,
			usb->interface_index,
			NULL,
			0,
			ZET030_FLUSH_TIMEOUT);
	libusb_bulk_transfer(usb->handle, usb->ep_rsp, usb->trbuf_rsp, ZET030_RSP_BUFSIZE, &r, ZET030_FLUSH_TIMEOUT);
	libusb_bulk_transfer(usb->handle, usb->ep_adc, usb->trbuf_adc[0], ZET030_ADC_BUFSIZE, &r, ZET030_FLUSH_TIMEOUT);

	d->tx_cmd.device = d;
	d->rx_rsp.device = d;
	d->rx_adc.device = d;

	usb->tr_cmd = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(usb->tr_cmd,
			usb->handle,
			usb->ep_cmd,
			d->tx_cmd.buf,
			0, /* to be filled */
			zet030_usb_handle_tx_cmd_transfer,
			NULL,
			ZET030_TX_TIMEOUT);

	usb->tr_rsp = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(usb->tr_rsp,
			usb->handle,
			usb->ep_rsp,
			usb->trbuf_rsp,
			ZET030_RSP_BUFSIZE,
			zet030_usb_handle_rx_transfer,
			NULL,
			ZET030_RX_TIMEOUT);
	if (libusb_submit_transfer(usb->tr_rsp) == 0)
		usb->tr_rsp->user_data = &d->rx_rsp;
	else
		zet030_set_state(d, ZET030_STATE_CLOSING);

	for (i = 0; i < ZET030_ADC_BUFCOUNT; i++) {
		usb->tr_adc[i] = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(usb->tr_adc[i],
				usb->handle,
				usb->ep_adc,
				usb->trbuf_adc[i],
				ZET030_ADC_BUFSIZE,
				zet030_usb_handle_rx_transfer,
				NULL,
				ZET030_RX_TIMEOUT);
		if (libusb_submit_transfer(usb->tr_adc[i]) == 0)
			usb->tr_adc[i]->user_data = &d->rx_adc;
		else
			zet030_set_state(d, ZET030_STATE_CLOSING);
	}

	zet030_build_device_time(d);
	zet030_set_state(d, ZET030_STATE_CONNECTED);
	//zet030_send_device_time(d, NULL);

	r = 0;
	if (zet030_lock_api_work(d) == ZET030_API_STATE_PROCESSING) {
		if (d->api_context.connect.cb) {
			d->api_context.connect.cb(d, d->api_context.connect.cb_arg, r);
			d->api_state = ZET030_API_STATE_IDLE;
			d->api_request = ZET030_API_REQUEST_NOP;
			osal_mutex_unlock(&d->api_lock);
		} else {
			zet030_unlock_api_work(d, r);
		}
	}

	while (zet030_get_state(d) == ZET030_STATE_CONNECTED) {
		if (d->tx_cmd.avail == 0 && !usb->tr_cmd->user_data)
			zet030_build_tx(d);

		if (d->tx_cmd.avail) {
			usb->tr_cmd->length = d->tx_cmd.avail;
			if (libusb_submit_transfer(usb->tr_cmd) == 0)
				usb->tr_cmd->user_data = &d->tx_cmd;
			else
				zet030_set_state(d, ZET030_STATE_CLOSING);
			d->tx_cmd.avail = 0;
		}

		r = libusb_handle_events(usb->ctx);
		if (r != 0) {
			switch (r) {
			case LIBUSB_ERROR_BUSY:
			case LIBUSB_ERROR_TIMEOUT:
			case LIBUSB_ERROR_OVERFLOW:
			case LIBUSB_ERROR_INTERRUPTED:
				break;
			default:
				zet030_set_state(d, ZET030_STATE_CLOSING);
				break;
			}
		}
	}

	zet030_set_state(d, ZET030_STATE_CLOSING);

	libusb_cancel_transfer(usb->tr_wakeup);
	libusb_cancel_transfer(usb->tr_cmd);
	libusb_cancel_transfer(usb->tr_rsp);
	for (i = 0; i < ZET030_ADC_BUFCOUNT; i++)
		libusb_cancel_transfer(usb->tr_adc[i]);

	while (zet030_usb_check_transfer_stopped(usb) != 0) {
		r = libusb_handle_events(usb->ctx);
	}

	libusb_free_transfer(usb->tr_cmd);
	libusb_free_transfer(usb->tr_rsp);
	for (i = 0; i < ZET030_ADC_BUFCOUNT; i++)
		libusb_free_transfer(usb->tr_adc[i]);

	/* fail any pending request */
	switch (zet030_lock_api_work(d)) {
	case ZET030_API_STATE_REQUESTED:
	case ZET030_API_STATE_PROCESSING:
		zet030_unlock_api_work(d, ZET030_ERROR_CLOSED);
		break;
	}
}

static void zet030_usb_wakeup(struct zet030_device *d)
{
	struct zet030_usb *usb = (struct zet030_usb *)d;

	if (libusb_submit_transfer(usb->tr_wakeup) == 0)
		usb->tr_wakeup->user_data = usb;
}

static void zet030_usb_free(struct zet030_device *d)
{
	struct zet030_usb *usb = (struct zet030_usb *)d;

	libusb_free_transfer(usb->tr_wakeup);

	libusb_release_interface(usb->handle, usb->interface_index);
	libusb_close(usb->handle);

	libusb_exit(usb->ctx);

	osal_free(usb);
}

// Path consists of bus number B and port numbers P: "B-P[.P]+"
// Based on libusb/hid.c from https://github.com/libusb/hidapi
static int zet030_usb_fill_path(struct libusb_device *dev, char *path, size_t path_size)
{
	uint8_t port_list[8];
	int port_count;
	int port_idx;
	int len;
	int left;

	if (!dev || !path || path_size <= 0)
		return 0;

	len = 0;

	port_count = libusb_get_port_numbers(dev, port_list, sizeof(port_list));
	if (port_count > 0) {
		left = (int)path_size;
		len = snprintf(path, left, "%u-%u", libusb_get_bus_number(dev), port_list[0]);
		for (port_idx = 1; port_idx < port_count; port_idx++) {
			if (len >= left) {
				len = 0;
				break;
			}
			left -= len;
			len += snprintf(&path[len], left, ".%u", port_list[port_idx]);
		}
	}

	path[len] = '\0';
	return len;
}

// enumerate devices with VID and PID
static int zet030_usb_enumerate(struct libusb_context *ctx, zet030_usb_enumerate_callback cb, void *arg)
{
	char path[64];
	struct libusb_device **list;
	ssize_t list_size;
	struct libusb_device_descriptor desc;
	struct libusb_device *dev;
	ssize_t i;
	int count;

	count = 0;

	list_size = libusb_get_device_list(ctx, &list);
	for (i = 0; i < list_size; i++) {
		dev = list[i];
		if (libusb_get_device_descriptor(dev, &desc) != 0)
			continue;
		if (desc.idVendor != ZET030_VID)
			continue;
//		if (desc.idProduct != ZET030_P_PID && desc.idProduct != ZET030_I_PID)
//			continue;
		if (zet030_usb_fill_path(dev, path, sizeof(path)) <= 0)
			continue;

		count++;
		if (cb(arg, dev, &desc, path) < 0)
			break;
	}

	libusb_free_device_list(list, 1);
	return count;
}

// parse serial hex string
static uint32_t zet030_usb_read_serial(struct libusb_device_handle *handle)
{
	char str[32];
	struct libusb_device_descriptor desc;
	uint32_t serial;
	char *endptr;

	if (libusb_get_device_descriptor(libusb_get_device(handle), &desc) != 0)
		return 0;

	if (libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, str, sizeof(str)) <= 0)
		return 0;
	str[sizeof(str) - 1] = '\0';

	serial = strtoul(str, &endptr, 16);
	if (!endptr || *endptr != '\0')
		return 0;

	return serial;
}

static int zet030_usb_handle_scan_enum(void *arg, struct libusb_device *dev, const struct libusb_device_descriptor *desc, const char *path)
{
	struct zet030_scan_info *info;
	struct libusb_device_handle *handle;
	uint32_t serial;

	info = arg;

	serial = 0;
	if (libusb_open(dev, &handle) >= 0) {
		serial = zet030_usb_read_serial(handle);
		libusb_close(handle);
	}

	return info->cb(info->arg, path, desc->idProduct, serial);
}

static struct zet030_device *zet030_usb_make_device(struct libusb_context *ctx, struct libusb_device_handle *handle)
{
	struct zet030_usb *usb;
	struct libusb_config_descriptor *config;
	const struct libusb_interface_descriptor *itf_desc;
	const struct libusb_endpoint_descriptor *ep_desc;
	uint8_t itf;
	uint8_t epi;

	usb = osal_malloc(sizeof(*usb));
	memset(usb, 0x00, sizeof(struct zet030_usb));

	usb->device.backend.run = zet030_usb_run;
	usb->device.backend.wakeup = zet030_usb_wakeup;
	usb->device.backend.free = zet030_usb_free;

	usb->ctx = ctx;
	usb->handle = handle;
	usb->dev = libusb_get_device(handle);

	usb->serial = zet030_usb_read_serial(handle);

	usb->interface_index = -1;

	usb->ep_cmd = 0;
	usb->ep_rsp = 0;
	usb->ep_adc = 0;
	usb->ep_dac = 0;

	usb->device.rx_rsp.pos = 0;
	usb->device.rx_adc.pos = 0;

	if (libusb_get_active_config_descriptor(usb->dev, &config) != 0) {
		libusb_close(handle);
		libusb_exit(ctx);
		osal_free(usb);
		return NULL;
	}

	for (itf = 0; itf < config->bNumInterfaces; itf++) {
		if (config->interface[itf].num_altsetting > 1)
			continue;
		
		itf_desc = &config->interface[itf].altsetting[0];
		if (itf_desc->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC)
			continue;

		for (epi = 0; epi < itf_desc->bNumEndpoints; epi++) {
			ep_desc = &itf_desc->endpoint[epi];
			if ((ep_desc->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK)
				continue;

			if ((ep_desc->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
				if (usb->ep_rsp == 0)
					usb->ep_rsp = ep_desc->bEndpointAddress;
				else if (usb->ep_adc == 0)
					usb->ep_adc = ep_desc->bEndpointAddress;
			} else {
				if (usb->ep_cmd == 0)
					usb->ep_cmd = ep_desc->bEndpointAddress;
				else if (usb->ep_dac == 0)
					usb->ep_dac = ep_desc->bEndpointAddress;
			}
		}
		if (usb->ep_cmd != 0 && usb->ep_rsp != 0) {
			usb->interface_index = itf;
			break;
		}
	}
	libusb_free_config_descriptor(config);

	if (usb->interface_index < 0) {
		libusb_close(handle);
		libusb_exit(ctx);
		osal_free(usb);
		return NULL;
	}

	if (libusb_claim_interface(usb->handle, usb->interface_index) != 0) {
		libusb_close(handle);
		libusb_exit(ctx);
		osal_free(usb);
		return NULL;
	}

	/* create here because it's used outside device thread */
	usb->tr_wakeup = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(usb->tr_wakeup,
			usb->handle,
			usb->ep_cmd,
			NULL, // !!!!
			0,
			zet030_usb_handle_wakeup_transfer,
			NULL,
			ZET030_TX_TIMEOUT);

	usb->device.api_context.connect.cb = NULL;
	usb->device.api_context.connect.cb_arg = NULL;

	if (zet030_init_device(&usb->device, ZET030_API_TIMEOUT) < 0) {
		zet030_close(&usb->device);
		return NULL;
	}

	return &usb->device;
}

static int zet030_usb_handle_open_enum(void *arg, struct libusb_device *dev, const struct libusb_device_descriptor *desc, const char *path)
{
	struct zet030_open_info *info;

	info = arg;

	if (info->path && strcmp(info->path, path) == 0) {
		// matched path
		if (libusb_open(dev, &info->handle) != 0) {
			info->handle = NULL;
		}
		return -1; // stop enumerating
	}

	if (info->serial != 0) {
		// first open device to read serial
		if (libusb_open(dev, &info->handle) >= 0) {
			if (info->serial == zet030_usb_read_serial(info->handle)) {
				// matched serial - leave open
				return -1; // stop enumerating
			}
			libusb_close(info->handle);
		}
		info->handle = NULL;
	}

	return 0;
}

int zet030_scan(zet030_scan_callback cb, void *arg)
{
	struct zet030_scan_info info;
	struct libusb_context *ctx;
	int r;

	info.cb = cb;
	info.arg = arg;

	if (libusb_init(&ctx) != 0)
		return ZET030_ERROR_IO;

	r = zet030_usb_enumerate(ctx, zet030_usb_handle_scan_enum, &info);

	libusb_exit(ctx);
	return r;
}

struct zet030_device *zet030_open_path(const char *path)
{
	struct zet030_open_info info;
	struct libusb_context *ctx;

	if (!path || path[0] == '\0')
		return NULL;

	info.path = path;
	info.serial = 0;
	info.handle = NULL;

	if (libusb_init(&ctx) != 0)
		return NULL;

	zet030_usb_enumerate(ctx, zet030_usb_handle_open_enum, &info);
	if (!info.handle) {
		libusb_exit(ctx);
		return NULL;
	}

	return zet030_usb_make_device(ctx, info.handle);
}

struct zet030_device *zet030_open_serial(uint32_t serial)
{
	struct zet030_open_info info;
	struct libusb_context *ctx;

	if (serial == 0)
		return NULL;

	info.path = NULL;
	info.serial = serial;
	info.handle = NULL;

	if (libusb_init(&ctx) != 0)
		return NULL;

	zet030_usb_enumerate(ctx, zet030_usb_handle_open_enum, &info);
	if (!info.handle) {
		libusb_exit(ctx);
		return NULL;
	}

	return zet030_usb_make_device(ctx, info.handle);
}
