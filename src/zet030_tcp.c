
#include "zet030.h"
#include "zet030_common.h"

#if ZSP_POSIX
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#endif

#if ZSP_WINAPI
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32")
#endif

#define ZET030_DEFAULT_PORT 1832

#define ZET030_CONNECT_TIMEOUT 10000

#define ZET030_RCVBUF 1048576
#define ZET030_KEEPALIVE 20

struct zet030_tcp {
	struct zet030_device device;

	struct in_addr ip;
	uint16_t port;

	int wakeup_pipe[2];
};

static void zet030_tcp_make_nonblocking(int fd)
{
#if ZSP_POSIX
	if (fd != -1) {
		(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	}
#endif
#if ZSP_WINAPI
	u_long optval;

	if (fd != -1) {
		optval = 1; /* nonblocking */
		(void)ioctlsocket(fd, FIONBIO, &optval);
	}
#endif
}

static int zet030_tcp_recv_rx(struct zet030_device *d, struct zet030_rx *rx, int fd)
{
	const struct zsp_header *h;
	const uint8_t *cur;
	int r;

	r = recv(fd, &rx->buf[rx->pos], ZET030_RX_BUFSIZE - rx->pos, 0);
	if (r <= 0)
		return -1;

	rx->pos += r;

	cur = rx->buf;
	r = rx->pos;
	while (r >= sizeof(struct zsp_header)) {
		h = (const struct zsp_header *)cur;
		if (h->full_size < sizeof(struct zsp_header) || h->full_size > ZET030_RX_BUFSIZE) {
			/* packet sync lost */
			rx->pos = 0;
			return -1;
		}
		if (r < h->full_size)
			break;

		zet030_parse_rx(d, h, cur + sizeof(struct zsp_header));

		cur += h->full_size;
		r -= h->full_size;
	}

	if (r > 0)
		memmove(rx->buf, cur, r);
	rx->pos = r;
	return 0;
}

static int zet030_tcp_send_tx(struct zet030_device *d, struct zet030_tx *tx, int fd)
{
	int r;

	r = send(fd, (const char *)&tx->buf[tx->pos], tx->avail, 0);
	if (r <= 0 || r > tx->avail)
		return -1;

	tx->avail -= r;
	if (tx->avail == 0)
		tx->pos = 0;
	else
		tx->pos += r;
	return 0;
}

static int zet030_tcp_add_wakeup_fd(struct zet030_tcp *tcp, fd_set *rfds)
{
#if ZSP_POSIX
	/* flush read end of the pipe, ignore return code */
	char data[8];

	(void)read(tcp->wakeup_pipe[0], data, sizeof(data));
#endif
#if ZSP_WINAPI
	if (tcp->wakeup_pipe[0] == -1) {
		tcp->wakeup_pipe[0] = (int)socket(PF_INET, SOCK_DGRAM, 0);
		zet030_tcp_make_nonblocking(tcp->wakeup_pipe[0]);
	}
#endif

	FD_SET(tcp->wakeup_pipe[0], rfds);
	return tcp->wakeup_pipe[0];
}

#if ZSP_WINAPI
static int zet030_tcp_init_winsock(void)
{
	WSADATA wsadata;

	return WSAStartup(MAKEWORD(2, 2), &wsadata);
}
#endif

static int zet030_tcp_connect_socket(struct zet030_tcp *tcp, const struct in_addr *ip, uint16_t port)
{
	int fd;
	int r;
	fd_set rfds;
	fd_set wfds;
	struct sockaddr_in addr;
	struct timeval tv;
	int optval;
	int optlen;

	fd = (int)socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		return -1;

	zet030_tcp_make_nonblocking(fd);

	addr.sin_family = AF_INET;
	addr.sin_addr = *ip;
	addr.sin_port = htons(port);
	r = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
	if (r == 0)
		return fd;

#if ZSP_WINAPI
	r = WSAGetLastError();
	if (r != WSAEWOULDBLOCK && r != WSAEINPROGRESS) {
		closesocket(fd);
		return -1;
	}
#endif
#if ZSP_POSIX
	if (errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
#endif

	FD_ZERO(&rfds);
	zet030_tcp_add_wakeup_fd(tcp, &rfds);

	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	r = select(fd + 1, &rfds, &wfds, NULL, &tv);
	if (r != -1 && r != 0 && FD_ISSET(fd, &wfds) && zet030_check_open(&tcp->device) != ZET030_ERROR_CLOSED) {
		optlen = sizeof(optval);
		r = getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&optval, &optlen);
		if (r == 0 && optval == 0) {
			optlen = sizeof(optval);

			optval = ZET030_RCVBUF;
			(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&optval, optlen);

			optval = 1;
			(void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&optval, optlen);

#if defined(TCP_KEEPALIVE)
			optval = ZET030_KEEPALIVE;
			(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (const char *)&optval, optlen);
#elif defined(TCP_KEEPIDLE)
			opt = ZET030_KEEPALIVE;
			(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (const char *)&optval, optlen);
#endif

#if defined(TCP_KEEPINTVL)
			optval = 1;
			(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char *)&optval, optlen);
#endif

#if defined(TCP_KEEPCNT)
			optval = 10;
			(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (const char *)&optval, optlen);
#endif
			return fd;
		}
	}

#if ZSP_WINAPI
	closesocket(fd);
#endif
#if ZSP_POSIX
	close(fd);
#endif
	return -1;
}

static void zet030_tcp_run(struct zet030_device *d)
{
	struct zet030_tcp *tcp = (struct zet030_tcp *)d;
	int cmd;
	int adc;
	fd_set rfds;
	fd_set wfds;
	int maxfd;
	struct timeval tv;
	int r;

	if (zet030_lock_api_work(d) != ZET030_API_STATE_REQUESTED) {
		zet030_set_state(d, ZET030_STATE_CLOSING);
		return;
	}

	if (d->api_request != ZET030_API_REQUEST_CONNECT) {
		zet030_set_state(d, ZET030_STATE_CLOSING);
		zet030_unlock_api_work(d, ZET030_ERROR_CLOSED);
		return;
	}

	zet030_unlock_api_work(d, ZET030_ERROR_BUSY);

	cmd = -1;
	adc = -1;
	r = ZET030_ERROR_CLOSED;

	cmd = zet030_tcp_connect_socket(tcp, &tcp->ip, tcp->port);
	if (cmd != -1) {
		adc = zet030_tcp_connect_socket(tcp, &tcp->ip, tcp->port + 1);
		if (adc != -1) {
			r = 0;
			zet030_set_state(d, ZET030_STATE_CONNECTED);
			zet030_build_device_time(d);
		}
	}

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
		FD_ZERO(&rfds);
		maxfd = zet030_tcp_add_wakeup_fd(tcp, &rfds);

		FD_SET(cmd, &rfds);
		if (maxfd < cmd)
			maxfd = cmd;

		FD_SET(adc, &rfds);
		if (maxfd < adc)
			maxfd = adc;

		if (!d->tx_cmd.avail)
			zet030_build_tx(d);

		if (d->tx_cmd.avail) {
			FD_ZERO(&wfds);
			FD_SET(cmd, &wfds);
		}

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		r = select(maxfd + 1, &rfds, d->tx_cmd.avail ? &wfds : NULL, NULL, &tv);

		if (r == -1)
			break;

		if (r == 0)
			continue;

		if (FD_ISSET(adc, &rfds)) {
			/* receive and parse adc data */
			r = zet030_tcp_recv_rx(d, &d->rx_adc, adc);
			if (r == -1)
				break;
		}

		if (FD_ISSET(cmd, &rfds)) {
			/* receive and parse response */
			r = zet030_tcp_recv_rx(d, &d->rx_rsp, cmd);
			if (r == -1)
				break;
		}

		if (d->tx_cmd.avail > 0 && FD_ISSET(cmd, &wfds)) {
			r = zet030_tcp_send_tx(d, &d->tx_cmd, cmd);
			if (r == -1)
				break;
		}
	}

#if ZSP_POSIX
	if (cmd != -1) {
		shutdown(cmd, SHUT_WR);
		close(cmd);
	}
	if (adc != -1) {
		shutdown(adc, SHUT_WR);
		close(adc);
	}
#endif
#if ZSP_WINAPI
	if (cmd != -1) {
		shutdown(cmd, SD_SEND);
		closesocket(cmd);
	}
	if (adc != -1) {
		shutdown(adc, SD_SEND);
		closesocket(adc);
	}
#endif

	/* fail any pending request */
	switch (zet030_lock_api_work(d)) {
	case ZET030_API_STATE_REQUESTED:
	case ZET030_API_STATE_PROCESSING:
		zet030_unlock_api_work(d, ZET030_ERROR_CLOSED);
		break;
	}
}

#if ZSP_POSIX
static void zet030_tcp_wakeup(struct zet030_device *d)
{
	struct zet030_tcp *tcp = (struct zet030_tcp *)d;
	uint8_t data;
	int r;

	data = 0;
	r = write(tcp->wakeup_pipe[1], &data, 1);
}
#endif

#if ZSP_WINAPI
static void WINAPI zet030_tcp_handle_wakeup_apc(ULONG_PTR param)
{
	struct zet030_tcp *tcp = (struct zet030_tcp *)param;

	if (tcp->wakeup_pipe[0] != -1) {
		/* socket close operation wakes up select() */
		closesocket(tcp->wakeup_pipe[0]);
		tcp->wakeup_pipe[0] = -1;
	}
}

static void zet030_tcp_wakeup(struct zet030_device *d)
{
	struct zet030_tcp *tcp = (struct zet030_tcp *)d;

	/* socket close operation must be performed by handling thread */
	QueueUserAPC(zet030_tcp_handle_wakeup_apc, d->thread, (ULONG_PTR)tcp);
}
#endif

static void zet030_tcp_free(struct zet030_device *d)
{
	struct zet030_tcp *tcp = (struct zet030_tcp *)d;

#if ZSP_POSIX
	close(tcp->wakeup_pipe[1]);
	close(tcp->wakeup_pipe[0]);
#endif
#if ZSP_WINAPI
	if (tcp->wakeup_pipe[0] != -1)
		closesocket(tcp->wakeup_pipe[0]);
#endif

	osal_free(tcp);
}

static int zet030_tcp_parse_path(const char *path, struct in_addr *ip, uint16_t *port)
{
	uint8_t temp_ip[4];
	uint16_t temp_port;
	int index; /* 0,1,2,3 for ip4 parts, 4 optional for port */
	int ndigs;
	int num;
	char ch;

	index = 0;
	ndigs = 0;
	num = 0;

	temp_port = ZET030_DEFAULT_PORT;

	while ((ch = *path++) != '\0') {
		if (ch >= '0' && ch <= '9') {
			if (ndigs == 0 && index > 4)
				return -1;
			if (ndigs > 0 && num == 0) /* leading zero 0xx */
				return -1;

			num = num * 10 + (ch - '0');
			ndigs++;

			if (index < 4) { /* ip4 */
				if (num > 255)
					return -1;
				if (ndigs > 3) /* more than 3 digits 123x */
					return -1;
				temp_ip[index] = num;
			} else { /* port */
				if (num > 65535)
					return -1;
				if (ndigs > 5) /* more than 5 digits 12345x */
					return -1;
				temp_port = num;
			}
			continue;
		}

		if (ndigs == 0) /* no digits */
			return -1;
		ndigs = 0;
		num = 0;
		index++;

		if (ch == '.') {
			if (index > 3)
				return -1;
			continue;
		}

		if (ch == ':') {
			if (index != 4)
				return -1;
			continue;
		}

		return -1;
	}

	if (index < 3 || index > 4)
		return -1;
	if (temp_ip[0] == 0 && temp_ip[1] == 0 && temp_ip[2] == 0 && temp_ip[3] == 0)
		return -1;
	if (temp_port == 0)
		return -1;

	memcpy(ip, temp_ip, sizeof(temp_ip));
	*port = temp_port;
	return 0;
}

struct zet030_device *zet030_connect(const char *path, zet030_connect_callback cb, void *arg)
{
	struct zet030_tcp *tcp;

#if ZSP_WINAPI
	if (zet030_tcp_init_winsock() != 0)
		return NULL;
#endif

	tcp = osal_malloc(sizeof(struct zet030_tcp));
	if (!tcp) {
		return NULL;
	}
	memset(tcp, 0x00, sizeof(struct zet030_tcp));

	if (zet030_tcp_parse_path(path, &tcp->ip, &tcp->port) != 0) {
		osal_free(tcp);
		return NULL;
	}

	tcp->device.backend.run = zet030_tcp_run;
	tcp->device.backend.wakeup = zet030_tcp_wakeup;
	tcp->device.backend.free = zet030_tcp_free;

#if ZSP_POSIX
	if (pipe(tcp->wakeup_pipe) == -1) {
		tcp->wakeup_pipe[0] = -1;
		tcp->wakeup_pipe[1] = -1;
	}
#endif
#if ZSP_WINAPI
	tcp->wakeup_pipe[0] = (int)socket(PF_INET, SOCK_DGRAM, 0);
	tcp->wakeup_pipe[1] = -1;
#endif
	if (tcp->wakeup_pipe[0] == -1) {
		osal_free(tcp);
		return NULL;
	}
	zet030_tcp_make_nonblocking(tcp->wakeup_pipe[0]);
	zet030_tcp_make_nonblocking(tcp->wakeup_pipe[1]);

	tcp->device.api_context.connect.cb = cb;
	tcp->device.api_context.connect.cb_arg = arg;

	if (zet030_init_device(&tcp->device, cb ? 0 : ZET030_CONNECT_TIMEOUT) < 0) {
		zet030_close(&tcp->device);
		return NULL;
	}

	return &tcp->device;
}
