#include "zet030.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct stream_stats {
	struct zet030_stream_time time;

	uint64_t size_per_sec;
	uint64_t size_total;
};

static int handle_scan(void *arg, const char *path, uint16_t pid, uint32_t serial)
{
	printf(" - detected: path=\"%s\" serial=%u\n", path, serial);
	return 0;
}

static int handle_stream(struct zet030_device *d, void *arg, const int32_t *data, int size, const struct zet030_stream_time *time)
{
	struct stream_stats *stats = arg;

	if (stats->time.utc != time->utc) {
		printf("Stream time %llu size %llu total %llu\n", time->utc, stats->size_per_sec, stats->size_total);
		stats->size_per_sec = 0;
	}

	stats->size_per_sec += size;
	stats->size_total += size;
	stats->time = *time;
	return 0;
}

static int handle_load_print(struct zet030_device *d, void *arg, uint32_t offset, const void *data, int size)
{
	char *s = (char *)malloc(size + 1);
	if (s) {
		memcpy(s, data, size);
		s[size] = '\0';
		printf("%s", s);
		free(s);
	}
	return 0;
}

static int handle_load_file(struct zet030_device *d, void *arg, uint32_t offset, const void *data, int size)
{
	FILE *f = (FILE *)arg;
	if (!f)
		return 0;

	long int pos = ftell(f);
	if (pos != offset)
		return 0;

	size_t r = fwrite(data, 1, size, f);
	return r == size ? 0 : -1;
}

static int handle_save_file(struct zet030_device *d, void *arg, uint32_t offset, void *buf, int max_size)
{
	FILE *f = (FILE *)arg;
	if (!f)
		return 0;

	long int pos = ftell(f);
	if (pos != offset)
		return 0;

	size_t r = fread(buf, 1, max_size, f);
	return (r > 0 ? (int)r : 0);
}

// return true if str is a prefix of full_str
static int is_prefixof(const char *str, const char *full_str)
{
	return (strncmp(str, full_str, strlen(str)) == 0);
}

// return input string length, or -1 if no eol (enter) found
static int wait_user_input(char *s, int len)
{
	size_t eol;

	fflush(stdout);

	if (!fgets(s, len, stdin))
		return -1;

	eol = strcspn(s, "\n\r");
	if (s[eol] != '\0') {
		if (eol > INT_MAX)
			return -1;
		s[eol] = '\0';
		return (int)eol;
	}

	while (s[eol] == '\0') {
		if (!fgets(s, len, stdin))
			return -1;
		eol = strcspn(s, "\n\r");
	}
	return -1;
}

static int device_menu(struct zet030_device *d, const char *path_or_serial)
{
	char s[256];
	char path[256];
	struct stream_stats stats;
	int return_code;
	int r;

	return_code = 0;
	while (1) {
		printf("[%s] Type command (or 'help'): ", path_or_serial);
		if (wait_user_input(s, sizeof(s)) <= 0)
			continue;

		if (is_prefixof(s, "help")) {
			printf("  start  - start stream\n");
			printf("  read   - read config\n");
			printf("  load   - load file\n");
			printf("  save   - save file\n");
			printf("  delete - delete file\n");
			printf("  talk   - talk to device\n");
			printf("  reboot - reboot\n");
			printf("  close  - close device\n");
			printf("  quit   - quit program\n");
			printf("  help   - show this help\n");
			continue;
		}

		if (is_prefixof(s, "close")) {
			printf("\nDevice closed\n");
			break;
		}
		if (is_prefixof(s, "quit") || strcmp(s, "exit") == 0) {
			printf("\nBye-bye!\n");
			return_code = -1;
			break;
		}

		r = zet030_check_open(d);
		if (r < 0) {
			printf("\nDevice closed\n");
			break;
		}

		if (is_prefixof(s, "start")) {
			memset(&stats, 0x00, sizeof(stats));

			r = zet030_start(d, handle_stream, &stats);
			if (r < 0) {
				printf("Stream not started\n");
				continue;
			}

			printf("Stream started... type enter to stop\n");
			while (wait_user_input(s, sizeof(s)) < 0) { // allow empty string
				printf("[streaming] Type enter to stop\n");
			}

			r = zet030_stop(d);
			printf("Stream stopped, code %d\n", r);
			continue;
		}

		if (is_prefixof(s, "read")) {
			r = zet030_load(d, "conf.xml", handle_load_print, NULL);
			printf("\nload result %d\n", r);
			continue;
		}

		if (is_prefixof(s, "load")) {
			printf("[%s] Type load path: ", path_or_serial);
			if (wait_user_input(s, sizeof(s)) <= 0)
				continue;

			printf("[%s] Type output path: ", path_or_serial);
			if (wait_user_input(path, sizeof(path)) <= 0)
				continue;

			FILE *f = fopen(path, "rb");
			if (f) {
				char confirm[32];

				fclose(f);
				printf("File exists: %s\n", path);
				printf("Type 'yes' to overwrite: ");
				if (wait_user_input(confirm, sizeof(confirm)) <= 0)
					continue;
				if (!is_prefixof(confirm, "yes") && !is_prefixof(confirm, "YES"))
					continue;
			}

			f = fopen(path, "wb");
			if (!f) {
				printf("Could not create file: %s\n", s);
				continue;
			}

			r = zet030_load(d, s, handle_load_file, f);
			fclose(f);
			if (r < 0)
				remove(path);

			printf("load result %d\n", r);
			continue;
		}

		if (is_prefixof(s, "save")) {
			printf("[%s] Type save path: ", path_or_serial);
			if (wait_user_input(s, sizeof(s)) <= 0)
				continue;

			printf("[%s] Type input path: ", path_or_serial);
			if (wait_user_input(path, sizeof(path)) <= 0)
				continue;

			FILE *f = fopen(path, "rb");
			if (!f) {
				printf("file not found: %s\n", path);
				continue;
			}

			r = zet030_save(d, s, handle_save_file, f);
			fclose(f);

			printf("save result %d\n", r);
			continue;
		}

		if (is_prefixof(s, "delete")) {
			printf("[%s] Type device path: ", path_or_serial);
			if (wait_user_input(s, sizeof(s)) <= 0)
				continue;

			if (s[0]) {
				r = zet030_delete(d, s);
				printf("delete result %d\n", r);
			}
			continue;
		}

		if (is_prefixof(s, "talk")) {
			char response[256];

			while (1) {
				printf("[%s talking] Type request (empty string to quit): ", path_or_serial);
				if (wait_user_input(s, sizeof(s)) <= 0)
					break;

				r = zet030_talk(d, s, response, sizeof(response));
				printf("%s\n", response);
				printf("[%d]\n", r);
			}
			continue;
		}

		if (is_prefixof(s, "reboot")) {
			char response[32];

			r = zet030_talk(d, "reboot", response, 32);
			printf("[%s] reboot: %d \"%s\"\n", path_or_serial, r, r == 0 ? response : "");
			break;
		}

		printf("ERROR: unknown input\n");
	}

	return return_code;
}

static int main_menu(void)
{
	char s[256];
	int r;
	uint32_t serial;
	char *endptr;
	struct zet030_device *device;

	while (1) {
#if ZET030_WITH_USB
		printf("\nScanning USB...\n");
		r = zet030_scan(handle_scan, NULL);
		if (r >= 0)
			printf("Found: %u\n", r);
#endif

#if ZET030_WITH_TCP && ZET030_WITH_USB
		printf("Type ip:port or path or serial (or 'help'): ");
#elif ZET030_WITH_TCP
		printf("Type ip:port (or 'help'): ");
#elif ZET030_WITH_USB
		printf("Type path or serial (or 'help'): ");
#endif
		if (wait_user_input(s, sizeof(s)) <= 0)
			continue;

		if (is_prefixof(s, "quit") || strcmp(s, "exit") == 0) {
			printf("\nBye-bye!\n");
			break;
		}

		if (is_prefixof(s, "help")) {
#if ZET030_WITH_TCP
			printf("  <ip>[:port] - connect device using ip:port\n");
#endif
#if ZET030_WITH_USB
			printf("  <serial>    - open device using serial\n");
			printf("  <path>      - open device using path\n");
#endif
			printf("  quit        - quit program\n");
			printf("  help        - show this help\n");
			continue;
		}

		device = NULL;

		serial = strtoul(s, &endptr, 0);
		if (serial == 0 || !endptr) {
			printf("ERROR: unknown input\n");
			continue;
		}

		if (*endptr == '.') { // this is ip:port
#if ZET030_WITH_TCP
			printf("Connecting to \"%s\"...\n", s);
			device = zet030_connect(s, NULL, NULL);
			if (!device) {
				printf("ERROR: connect failed\n");
				continue;
			}
			printf("\nDevice connected\n\n");
#else
			printf("\nERROR: TCP is not supported\n");
#endif
		} else {
#if ZET030_WITH_USB
			if (*endptr == '-') { // this is path
				printf("Opening path \"%s\"\n", s);
				device = zet030_open_path(s);
			} else {
				printf("Opening device with serial %u\n", serial);
				device = zet030_open_serial(serial);
			}
			if (!device) {
				printf("ERROR: open failed\n");
				continue;
			}
			printf("\nDevice open\n\n");
#else
			printf("\nERROR: USB is not supported\n");
#endif
		}

		if (device) {
			r = device_menu(device, s);

			zet030_close(device);
			device = NULL;

			if (r < 0)
				break;
		}

	}

	return 0;
}

int main(void)
{
	printf("ZET 030 demo\n");

	main_menu();

	return 0;
}
