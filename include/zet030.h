/*
 * ZETLAB ZET 030 device library
 *
 * Copyright (c) 2023 ZETLAB (zetlab.com)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ZETLAB_ZET030_H
#define ZETLAB_ZET030_H

#include <stdint.h>

#define ZET030_LIB_DATE 20250625

/**
 * Opaque structure representing a device.
 */
struct zet030_device;

/**
 * Error codes.
 */
enum zet030_error {
	/** Generic error */
	ZET030_ERROR_OTHER = -1,

	/** Invalid parameter */
	ZET030_ERROR_INVALID_PARAMETER = -2,

	/** Device closed */
	ZET030_ERROR_CLOSED = -3,

	/** Requested file not found */
	ZET030_ERROR_FILE_NOT_FOUND = -4,

	/** Invalid file format */
	ZET030_ERROR_INVALID_FORMAT = -5,

	/** Insufficient memory */
	ZET030_ERROR_OUT_OF_MEMORY = -6,

	/** I/O error */
	ZET030_ERROR_IO = -7,

	/** Busy executing another user call */
	ZET030_ERROR_BUSY = -8,

	/** Busy processing data stream */
	ZET030_ERROR_STARTED = -9,

	/** Timeout */
	ZET030_ERROR_TIMEOUT = -10,

	/** Operation is not supported */
	ZET030_ERROR_NOT_SUPPORTED = -11,
};

/**
 * Log severity levels.
 */
enum zet030_log_level {
	/** Disable log messages */
	ZET030_LOG_LEVEL_OFF = 0,

	/** Critical errors, repair required */
	ZET030_LOG_LEVEL_FATAL = 0x20544146,

	/** Recoverable errors, measurements are impossible */
	ZET030_LOG_LEVEL_ERROR = 0x21525245,

	/** May impact measured values */
	ZET030_LOG_LEVEL_WARNING = 0x224E5257,

	/** Informational messages */
	ZET030_LOG_LEVEL_INFO = 0x23464E49,

	/** Debug messages, may be floody */
	ZET030_LOG_LEVEL_DEBUG = 0x24474244,
};

/**
 * Stream data time.
 */
struct zet030_stream_time {
	uint64_t utc;
	uint32_t counter;
};

/**
 * Function called by zet030_scan() on each detected device.
 * @param arg optional user context
 * @param path device path
 * @param serial device serial number, value 0 means device cannot be opened
 * @return 0 to continue scanning, negative value to stop scanning
 */
typedef int (*zet030_scan_callback)(void *arg, const char *path, uint16_t pid, uint32_t serial);

/**
 * Function called by device thread to report connection result.
 */
typedef int (*zet030_connect_callback)(struct zet030_device *d, void *arg, int status);

/**
 * Function called by device thread when some stream data arrived.
 * Function must not block for too long.
 * @param d device
 * @param arg optional user context
 * @param data data arrived, buffer valid only during function call
 * @return 0 to continue stream, negative value to stop stream
 */
typedef int (*zet030_stream_callback)(struct zet030_device *d, void *arg, const int32_t *data, int count, const struct zet030_stream_time *time);

/**
 * Function called by zet030_load() on next portion of loaded file data.
 * Data buffer invalidates when function exits.
 * @param d device
 * @param arg optional user context
 * @param offset file offset
 * @param data file data portion
 * @param size data size
 * @return 0 to continue loading, negative value to stop stream
 */
typedef int (*zet030_load_callback)(struct zet030_device *d, void *arg, uint32_t offset, const void *data, int size);

/**
 * Function called by zet030_save() to request next data to save.
 * Data size is not cache efficient.
 * @param d device
 * @param arg optional user context
 * @param offset file offset
 * @param data file data portion
 * @param size data size
 * @return 0 to continue loading, negative value to stop stream
 */
typedef int (*zet030_save_callback)(struct zet030_device *d, void *arg, uint32_t offset, void *buf, int max_size);

/**
 * Function called by device thread when log message is arrived.
 * @param d device
 * @param arg optional user context
 * @param utc device time of message
 * @param level @ref zet030_log_level
 * @param text message
 */
typedef int (*zet030_log_callback)(struct zet030_device *d, void *arg, uint64_t utc, enum zet030_log_level level, const char *text);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Scan for currenly available devices.
 * @param cb callback called on each detected device
 * @param arg user-specific arg passed to callback
 * @returns the number of detected devices, or @ref zet030_error
*/
int zet030_scan(zet030_scan_callback cb, void *arg);

/**
 * Open device with specified path.
 * @param path device path to open
 * @returns 0 on success, or @ref zet030_error
 */
struct zet030_device *zet030_open_path(const char *path);

/**
 * Open device with specified serial number.
 * @param serial serial number
 * @returns 0 on success, or @ref zet030_error
 */
struct zet030_device *zet030_open_serial(uint32_t serial);

/**
 * Open device with specified path.
 * If callback param is specified, function will return immediately.
 * If callback param is NULL, function will block.
 *
 * @param path device path to open "ip[:port]"
 * @param cb (optional) function to be called with connection result
 * @param arg (optional) user-specific argument to be passed to callback function
 * @returns pointer to device on success, or NULL on error
 */
struct zet030_device *zet030_connect(const char *path, zet030_connect_callback cb, void *arg);

/**
 * Close device and free associated resources.
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_close(struct zet030_device *d);

/**
 * Check whether device is still available.
 * @returns 0 on success, or ZET030_ERROR_BUSY if still connecting, or ZET03_ERROR_CLOSED
 */
int zet030_check_open(struct zet030_device *d);

/**
 * Start data (ADC) stream.
 * Function returns immediately, callback will be called
 * by device thread on next data portion.
 * To stop stream, call zet030_stop() or zet030_close().
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_start(struct zet030_device *d, zet030_stream_callback cb, void *arg);

/**
 * Stop stream.
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_stop(struct zet030_device *d);

/**
 * Load file from device storage.
 * Function call is blocking, callback is called after reading next portion of data.
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_load(struct zet030_device *d, const char *path, zet030_load_callback cb, void *arg);

/**
 * Save file into device storage.
 * Function call is blocking, callback is called before writing next portion of data.
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_save(struct zet030_device *d, const char *path, zet030_save_callback cb, void *arg);

/**
 * Delete file.
 *
 * @param d device
 * @param path path to file to be deleted
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_delete(struct zet030_device *d, const char *path);

/**
 * Talk to device, i.e. send textual request and receive response.
 * Function call is blocking.
 * Data stream can be either started or stopped.
 *
 * @param d device
 * @param text text to be sent to device
 * @param response buffer to be filled with response from device
 * @param response_size max response bytes (including terminating zero) that can be filled
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_talk(struct zet030_device *d, const char *text, char *response, int response_size);

/**
 * Subscribe to log messages from device.
 *
 * Function returns after performing subscribe request.
 * Log callback will be called by device thread when message arrived.
 * To cancel subscription, call with max_level == ZET030_LOG_LEVEL_OFF or with cb == NULL.
 *
 * @param d device
 * @param max_level trace message with @ref zet030_log_level equal to or lower than specified
 * @param 
 * @returns 0 on success, or @ref zet030_error
 */
int zet030_subscribe(struct zet030_device *d, enum zet030_log_level max_level, zet030_log_callback cb, void *arg);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
