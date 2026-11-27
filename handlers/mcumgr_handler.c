/*
 * (C) Copyright 2026
 * Joris Offouga, offougajoris@gmail.com.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

/*
 * Update an external microcontroller running Zephyr and MCUboot with
 * the MCUmgr SMP protocol over a UART (Zephyr MCUmgr UART transport).
 *
 *   1. upload the image to the secondary slot   (IMG group, upload)
 *   2. mark it for test                         (IMG group, state write)
 *   3. reset the MCU                            (OS group, reset)
 *   4. wait until MCUboot has swapped and the new image runs
 *   5. wait for the application to confirm the image (confirm = "mcu"),
 *      or confirm it from the handler (confirm = "host").
 *
 * If anything fails once the new image runs, the MCU is reset again: the
 * image was not confirmed, so MCUboot reverts to the previous one (swap
 * modes of MCUboot only).
 *
 * See doc/source/handlers.rst for the sw-description properties.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>

#include "swupdate_image.h"
#include "handler.h"
#include "util.h"
#include "mcumgr_smp.h"

#define RX_LINE_MAX		512
#define CBOR_OVERHEAD		64	/* map keys, offsets, lengths */

#define DEFAULT_BAUDRATE	115200
#define DEFAULT_CHUNK		128
#define DEFAULT_RETRIES		3
#define DEFAULT_TIMEOUT_MS	5000
#define DEFAULT_ERASE_TMO_MS	30000
#define DEFAULT_BOOT_TMO_MS	120000
#define DEFAULT_CONFIRM_TMO_MS	30000
#define POLL_INTERVAL_MS	1000
#define DRAIN_QUIET_MS		100
#define DRAIN_MAX_MS		1000

#define HASH_MAX		64

enum confirm_mode {
	CONFIRM_MCU,
	CONFIRM_HOST,
};

struct mcumgr {
	int fd;
	uint8_t seq;
	bool any_seq;	/* polling idempotent reads: accept late answers */

	/* configuration */
	unsigned int image;
	unsigned int chunk;
	unsigned int retries;
	unsigned int timeout_ms;
	unsigned int erase_timeout_ms;
	unsigned int boot_timeout_ms;
	unsigned int confirm_timeout_ms;
	enum confirm_mode confirm;

	/* upload state */
	uint8_t *chunkbuf;
	uint8_t *body;
	size_t bodycap;
	size_t fill;
	uint64_t off;
	uint64_t total;

	/* tx */
	uint8_t *pkt;
	uint8_t *frames;
	size_t framescap;

	/* rx */
	struct smp_serial_rx rx;
	uint8_t line[RX_LINE_MAX];
	size_t linelen;
	bool line_overflow;
};

struct slot_state {
	bool present;
	uint8_t hash[HASH_MAX];
	size_t hashlen;
	bool active;
	bool confirmed;
	bool pending;
};

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool same_hash(const struct slot_state *s, const uint8_t *hash,
		      size_t hashlen)
{
	return s->present && s->hashlen == hashlen &&
	       !memcmp(s->hash, hash, hashlen);
}

/* ------------------------------------------------------------------ */
/* UART                                                               */
/* ------------------------------------------------------------------ */

static speed_t baud_to_speed(unsigned int baud)
{
	switch (baud) {
	case 9600: return B9600;
	case 19200: return B19200;
	case 38400: return B38400;
	case 57600: return B57600;
	case 115200: return B115200;
	case 230400: return B230400;
	case 460800: return B460800;
	case 921600: return B921600;
	case 1000000: return B1000000;
	default: return 0;
	}
}

static int uart_open(const char *dev, speed_t speed)
{
	struct termios tty;
	int fd;

	fd = open(dev, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		ERROR("Cannot open %s: %s", dev, strerror(errno));
		return -ENODEV;
	}

	if (tcgetattr(fd, &tty)) {
		ERROR("tcgetattr %s: %s", dev, strerror(errno));
		close(fd);
		return -EIO;
	}
	cfmakeraw(&tty);
	cfsetispeed(&tty, speed);
	cfsetospeed(&tty, speed);
	tty.c_cflag |= CLOCAL | CREAD;
	tty.c_cflag &= ~(CSTOPB | CRTSCTS);
	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 0;
	if (tcsetattr(fd, TCSANOW, &tty)) {
		ERROR("tcsetattr %s: %s", dev, strerror(errno));
		close(fd);
		return -EIO;
	}
	tcflush(fd, TCIOFLUSH);
	return fd;
}

static int write_all(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;

	while (n) {
		ssize_t w = write(fd, p, n);

		if (w < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			ERROR("UART write: %s", strerror(errno));
			return -EIO;
		}
		p += w;
		n -= w;
	}
	return 0;
}

/*
 * Some USB-serial bridges (seen with OpenSDA / DAPLink) hold the last bytes
 * of a write until more data is sent: the end of a request reaches the MCU
 * only with the next request, and each answer arrives one request late.
 * An empty line is written after each request to push it through: the
 * Zephyr SMP transport ignores empty lines, and if the bridge holds this
 * byte instead, nothing is lost.
 */
static int uart_kick(struct mcumgr *m)
{
	return write_all(m->fd, "\n", 1);
}

/*
 * Discard the data still in transit when the UART is opened, for example
 * the answer to the last request of a previous session, pushed by the
 * first bytes written (see uart_kick()). Read until the line is quiet for
 * DRAIN_QUIET_MS, at most DRAIN_MAX_MS.
 */
static void rx_drain(struct mcumgr *m)
{
	uint64_t end = now_ms() + DRAIN_MAX_MS;
	size_t total = 0;

	while (now_ms() < end) {
		struct pollfd pfd = { .fd = m->fd, .events = POLLIN };
		uint8_t buf[256];
		ssize_t r;
		int ret;

		ret = poll(&pfd, 1, DRAIN_QUIET_MS);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;
		r = read(m->fd, buf, sizeof(buf));
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (r <= 0)
			break;
		total += r;
	}
	if (total)
		DEBUG("Discarded %zu bytes received before the first request",
		      total);
}

static void rx_flush(struct mcumgr *m)
{
	tcflush(m->fd, TCIFLUSH);
	m->linelen = 0;
	m->line_overflow = false;
	smp_serial_rx_reset(&m->rx);
}

/* Wait for any complete SMP packet until deadline. */
static int smp_recv(struct mcumgr *m, uint64_t deadline)
{
	for (;;) {
		uint64_t now = now_ms();
		struct pollfd pfd = { .fd = m->fd, .events = POLLIN };
		uint8_t buf[256];
		ssize_t r, i;
		int ret;

		if (now >= deadline)
			return -ETIMEDOUT;

		ret = poll(&pfd, 1, (int)(deadline - now));
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -EIO;
		}
		if (ret == 0)
			return -ETIMEDOUT;

		r = read(m->fd, buf, sizeof(buf));
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			ERROR("UART read: %s", strerror(errno));
			return -EIO;
		}

		for (i = 0; i < r; i++) {
			if (buf[i] == '\n') {
				int got = 0;

				if (!m->line_overflow)
					got = smp_serial_rx_line(&m->rx, m->line,
								 m->linelen);
				m->linelen = 0;
				m->line_overflow = false;
				if (got == -EBADMSG)
					WARN("Corrupted SMP frame, dropped");
				if (got == 1)
					return 0;
				continue;
			}
			if (m->linelen >= sizeof(m->line)) {
				m->line_overflow = true;
				continue;
			}
			m->line[m->linelen++] = buf[i];
		}
	}
}

/* ------------------------------------------------------------------ */
/* SMP requests                                                       */
/* ------------------------------------------------------------------ */

/* SMP v1 "rc" or SMP v2 "err": { "group", "rc" } */
static int smp_check_rc(const uint8_t *p, const uint8_t *end)
{
	const uint8_t *v;
	uint64_t rc = 0, group = 0;

	v = smp_cbor_map_get(p, end, "rc");
	if (v && smp_cbor_get_uint(v, end, &rc) && rc) {
		ERROR("MCU returned SMP error rc=%llu", (unsigned long long)rc);
		return -EIO;
	}
	v = smp_cbor_map_get(p, end, "err");
	if (v) {
		const uint8_t *g = smp_cbor_map_get(v, end, "group");
		const uint8_t *r = smp_cbor_map_get(v, end, "rc");

		if (g)
			smp_cbor_get_uint(g, end, &group);
		if (r)
			smp_cbor_get_uint(r, end, &rc);
		if (rc) {
			ERROR("MCU returned SMP error group=%llu rc=%llu",
			      (unsigned long long)group, (unsigned long long)rc);
			return -EIO;
		}
	}
	return 0;
}

/*
 * Send one request, wait for the matching response. The request is sent
 * again with the same sequence number if no answer arrives in time (lost
 * or corrupted frame): all the requests used here are idempotent, and an
 * upload chunk sent twice is answered with the next expected offset.
 * On success *rsp / *rsplen point to the CBOR payload in m->rx.
 */
static int smp_request(struct mcumgr *m, uint8_t op, uint16_t group,
		       uint8_t id, const uint8_t *body, size_t blen,
		       unsigned int timeout_ms, unsigned int retries,
		       const uint8_t **rsp, size_t *rsplen)
{
	uint8_t seq = m->seq++;
	unsigned int attempt;
	size_t n;
	int ret = -ETIMEDOUT;

	if (blen > m->bodycap)
		return -ENOMEM;

	m->pkt[0] = op & 0x07;	/* SMP version 0, widest compatibility */
	m->pkt[1] = 0;
	m->pkt[2] = blen >> 8;
	m->pkt[3] = blen & 0xff;
	m->pkt[4] = group >> 8;
	m->pkt[5] = group & 0xff;
	m->pkt[6] = seq;
	m->pkt[7] = id;
	memcpy(m->pkt + SMP_HDR_LEN, body, blen);

	n = smp_serial_encode(m->pkt, SMP_HDR_LEN + blen, m->frames,
			      m->framescap);
	if (!n)
		return -ENOMEM;

	for (attempt = 0; attempt <= retries; attempt++) {
		uint64_t deadline;

		if (attempt)
			WARN("No answer from MCU (group %u id %u), retry %u/%u",
			     group, id, attempt, retries);

		ret = write_all(m->fd, m->frames, n);
		if (!ret)
			ret = uart_kick(m);	/* separate write */
		if (ret)
			return ret;

		deadline = now_ms() + timeout_ms;
		for (;;) {
			const uint8_t *r = m->rx.buf;
			size_t len;

			ret = smp_recv(m, deadline);
			if (ret)
				break;
			if (m->rx.len < SMP_HDR_LEN)
				continue;

			len = (r[2] << 8) | r[3];
			if ((r[0] & 0x07) != op + 1 ||
			    ((r[4] << 8) | r[5]) != group ||
			    (!m->any_seq && r[6] != seq) || r[7] != id ||
			    SMP_HDR_LEN + len > m->rx.len) {
				DEBUG("Ignoring unrelated SMP response: op %u "
				      "group %u seq %u id %u len %zu/%zu (want "
				      "op %u group %u seq %u id %u)",
				      r[0] & 0x07, (r[4] << 8) | r[5], r[6],
				      r[7], len, m->rx.len - SMP_HDR_LEN,
				      op + 1, group, seq, id);
				continue;
			}

			*rsp = r + SMP_HDR_LEN;
			*rsplen = len;
			return smp_check_rc(*rsp, *rsp + len);
		}
		if (ret != -ETIMEDOUT)
			return ret;
	}
	return ret;
}

static int img_state_parse(struct mcumgr *m, const uint8_t *p,
			   const uint8_t *end, struct slot_state slots[2])
{
	const uint8_t *imgs = smp_cbor_map_get(p, end, "images");
	struct smp_cbor_iter it;

	memset(slots, 0, 2 * sizeof(*slots));
	if (!imgs || !smp_cbor_iter_init(&it, imgs, end, 4)) {
		ERROR("Image state response without 'images'");
		return -EPROTO;
	}

	while (smp_cbor_iter_next(&it)) {
		const uint8_t *e = it.p, *v, *h;
		uint64_t slot = 0, image = 0;
		size_t hlen;
		struct slot_state *s;

		it.p = smp_cbor_skip(e, end);
		if (!it.p)
			return -EPROTO;

		v = smp_cbor_map_get(e, end, "image");
		if (v)
			smp_cbor_get_uint(v, end, &image);
		v = smp_cbor_map_get(e, end, "slot");
		if (!v || !smp_cbor_get_uint(v, end, &slot) || slot > 1)
			continue;
		if (image != m->image)
			continue;

		s = &slots[slot];
		s->present = true;
		v = smp_cbor_map_get(e, end, "hash");
		if (v && smp_cbor_get_bstr(v, end, &h, &hlen) &&
		    hlen <= HASH_MAX) {
			memcpy(s->hash, h, hlen);
			s->hashlen = hlen;
		}
		v = smp_cbor_map_get(e, end, "active");
		if (v)
			smp_cbor_get_bool(v, end, &s->active);
		v = smp_cbor_map_get(e, end, "confirmed");
		if (v)
			smp_cbor_get_bool(v, end, &s->confirmed);
		v = smp_cbor_map_get(e, end, "pending");
		if (v)
			smp_cbor_get_bool(v, end, &s->pending);
	}
	return 0;
}

static int img_state_read(struct mcumgr *m, unsigned int tmo,
			  unsigned int retries, struct slot_state slots[2])
{
	uint8_t body[1] = { 0xa0 };	/* empty map */
	const uint8_t *rsp;
	size_t len;
	int ret;

	ret = smp_request(m, SMP_OP_READ, SMP_GRP_IMG, SMP_ID_IMG_STATE,
			  body, sizeof(body), tmo, retries, &rsp, &len);
	if (ret)
		return ret;
	return img_state_parse(m, rsp, rsp + len, slots);
}

static int img_state_write(struct mcumgr *m, const uint8_t *hash,
			   size_t hashlen, bool confirm,
			   struct slot_state slots[2])
{
	uint8_t body[128];
	struct smp_cbor_enc e = { .p = body, .cap = sizeof(body) };
	const uint8_t *rsp;
	size_t len;
	int ret;

	smp_cbor_map(&e, 2);
	smp_cbor_tstr(&e, "hash");
	smp_cbor_bstr(&e, hash, hashlen);
	smp_cbor_tstr(&e, "confirm");
	smp_cbor_bool(&e, confirm);
	if (e.err)
		return -ENOMEM;

	ret = smp_request(m, SMP_OP_WRITE, SMP_GRP_IMG, SMP_ID_IMG_STATE,
			  body, e.len, m->timeout_ms, m->retries, &rsp, &len);
	if (ret)
		return ret;
	return img_state_parse(m, rsp, rsp + len, slots);
}

/* Erase the secondary slot, used to cancel a pending image */
static int img_erase_secondary(struct mcumgr *m)
{
	uint8_t body[16];
	struct smp_cbor_enc e = { .p = body, .cap = sizeof(body) };
	const uint8_t *rsp;
	size_t len;

	smp_cbor_map(&e, 1);
	smp_cbor_tstr(&e, "slot");
	smp_cbor_uint(&e, 2 * m->image + 1);	/* slots of all images */
	if (e.err)
		return -ENOMEM;

	return smp_request(m, SMP_OP_WRITE, SMP_GRP_IMG, SMP_ID_IMG_ERASE,
			   body, e.len, m->erase_timeout_ms, m->retries,
			   &rsp, &len);
}

/* Not retried: the MCU may reset before its answer is sent */
static int os_reset(struct mcumgr *m)
{
	uint8_t body[1] = { 0xa0 };
	const uint8_t *rsp;
	size_t len;
	int ret;

	ret = smp_request(m, SMP_OP_WRITE, SMP_GRP_OS, SMP_ID_OS_RESET,
			  body, sizeof(body), m->timeout_ms, 0, &rsp, &len);
	if (ret == -ETIMEDOUT) {
		WARN("No answer to reset, assuming MCU is rebooting");
		ret = 0;
	}
	return ret;
}

/* ------------------------------------------------------------------ */
/* Upload                                                             */
/* ------------------------------------------------------------------ */

static int upload_chunk(struct mcumgr *m)
{
	struct smp_cbor_enc e = { .p = m->body, .cap = m->bodycap };
	bool first = (m->off == 0);
	const uint8_t *rsp, *v;
	size_t len;
	uint64_t off;
	int ret;

	smp_cbor_map(&e, first ? 4 : 2);
	if (first) {
		smp_cbor_tstr(&e, "image");
		smp_cbor_uint(&e, m->image);
		smp_cbor_tstr(&e, "len");
		smp_cbor_uint(&e, m->total);
	}
	smp_cbor_tstr(&e, "off");
	smp_cbor_uint(&e, m->off);
	smp_cbor_tstr(&e, "data");
	smp_cbor_bstr(&e, m->chunkbuf, m->fill);
	if (e.err)
		return -ENOMEM;

	/*
	 * If the chunk was received but the answer was lost, the retry is
	 * answered with the next offset: the chunk is not written twice.
	 */
	ret = smp_request(m, SMP_OP_WRITE, SMP_GRP_IMG, SMP_ID_IMG_UPLOAD,
			  m->body, e.len,
			  first ? m->erase_timeout_ms : m->timeout_ms,
			  m->retries, &rsp, &len);
	if (ret) {
		ERROR("Upload failed at offset %llu", (unsigned long long)m->off);
		return ret;
	}

	v = smp_cbor_map_get(rsp, rsp + len, "off");
	if (!v || !smp_cbor_get_uint(v, rsp + len, &off)) {
		ERROR("Upload response without 'off'");
		return -EPROTO;
	}
	if (off != m->off + m->fill) {
		/* streaming input: cannot seek, resync is not possible */
		ERROR("MCU expects offset %llu, sent up to %llu",
		      (unsigned long long)off,
		      (unsigned long long)(m->off + m->fill));
		return -EPROTO;
	}

	m->off = off;
	m->fill = 0;
	return 0;
}

/* copyimage() callback */
static int mcumgr_write(void *out, const void *buf, size_t len)
{
	struct mcumgr *m = out;
	const uint8_t *p = buf;

	while (len) {
		size_t n = m->chunk - m->fill;

		if (n > len)
			n = len;
		memcpy(m->chunkbuf + m->fill, p, n);
		m->fill += n;
		p += n;
		len -= n;

		if (m->fill == m->chunk) {
			int ret = upload_chunk(m);

			if (ret)
				return ret;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Boot and confirmation                                              */
/* ------------------------------------------------------------------ */

/*
 * Wait until the new image runs. The old image may still answer for a
 * while (CONFIG_MCUMGR_GRP_OS_RESET_MS): it is recognized because the new
 * image is still pending in the secondary slot.
 */
static int wait_new_image_active(struct mcumgr *m, const uint8_t *hash,
				 size_t hashlen, struct slot_state slots[2])
{
	uint64_t deadline = now_ms() + m->boot_timeout_ms;

	while (now_ms() < deadline) {
		int ret;

		m->any_seq = true;
		ret = img_state_read(m, POLL_INTERVAL_MS * 2, 0, slots);
		m->any_seq = false;

		if (ret == 0) {
			if (same_hash(&slots[0], hash, hashlen) &&
			    slots[0].active)
				return 0;

			if (same_hash(&slots[1], hash, hashlen) &&
			    slots[1].pending) {
				DEBUG("Previous image still running, waiting "
				      "for the reset");
			} else {
				ERROR("MCU booted, but new image is not active "
				      "(MCUboot rejected or reverted it)");
				return -EFAULT;
			}
		} else if (ret != -ETIMEDOUT && ret != -EIO) {
			return ret;
		}
		/* MCU not reset yet, swapping or booting: retry */
		usleep(POLL_INTERVAL_MS * 1000);
	}
	ERROR("New image not running after %u ms", m->boot_timeout_ms);
	return -ETIMEDOUT;
}

static int wait_mcu_confirm(struct mcumgr *m, struct slot_state slots[2])
{
	uint64_t deadline = now_ms() + m->confirm_timeout_ms;

	while (now_ms() < deadline) {
		int ret;

		m->any_seq = true;
		ret = img_state_read(m, m->timeout_ms, 0, slots);
		m->any_seq = false;
		if (ret == 0 && slots[0].confirmed)
			return 0;
		usleep(POLL_INTERVAL_MS * 1000);
	}
	ERROR("MCU application did not confirm the new image");
	return -ETIMEDOUT;
}

/*
 * Error after the image was marked for test, before it ran: the MCU
 * would test it at its next reset, although the update failed. Cancel
 * it by erasing the secondary slot (Zephyr refuses unless built with
 * CONFIG_MCUMGR_GRP_IMG_ALLOW_ERASE_PENDING).
 */
static void cancel_pending(struct mcumgr *m)
{
	if (img_erase_secondary(m) == 0) {
		WARN("mcumgr: pending image erased");
		return;
	}
	ERROR("mcumgr: cannot cancel the pending image: the MCU will test it "
	      "at its next reset");
}

/* ------------------------------------------------------------------ */
/* Handler                                                            */
/* ------------------------------------------------------------------ */

static int prop_uint(struct img_type *img, const char *name,
		     unsigned int def, unsigned int min, unsigned int max,
		     unsigned int *val)
{
	const char *v = dict_get_value(&img->properties, name);
	unsigned long long r;
	char *endp;

	if (!v) {
		*val = def;
		return 0;
	}
	errno = 0;
	r = strtoull(v, &endp, 10);
	if (*v < '0' || *v > '9' || errno || *endp || r < min || r > max) {
		ERROR("mcumgr: invalid value '%s' for %s (%u..%u)",
		      v, name, min, max);
		return -EINVAL;
	}
	*val = r;
	return 0;
}

static int parse_properties(struct img_type *img, struct mcumgr *m,
			    speed_t *speed)
{
	unsigned int baud;
	const char *confirm;
	int ret = 0;

	ret |= prop_uint(img, "baudrate", DEFAULT_BAUDRATE, 1, UINT_MAX,
			 &baud);
	ret |= prop_uint(img, "chunk-size", DEFAULT_CHUNK, 16, 4096,
			 &m->chunk);
	ret |= prop_uint(img, "image", 0, 0, 255, &m->image);
	ret |= prop_uint(img, "retries", DEFAULT_RETRIES, 0, 100,
			 &m->retries);
	ret |= prop_uint(img, "timeout-ms", DEFAULT_TIMEOUT_MS, 1, INT_MAX,
			 &m->timeout_ms);
	ret |= prop_uint(img, "erase-timeout-ms", DEFAULT_ERASE_TMO_MS, 1,
			 INT_MAX, &m->erase_timeout_ms);
	ret |= prop_uint(img, "boot-timeout-ms", DEFAULT_BOOT_TMO_MS, 1,
			 INT_MAX, &m->boot_timeout_ms);
	ret |= prop_uint(img, "confirm-timeout-ms", DEFAULT_CONFIRM_TMO_MS, 1,
			 INT_MAX, &m->confirm_timeout_ms);
	if (ret)
		return -EINVAL;

	*speed = baud_to_speed(baud);
	if (!*speed) {
		ERROR("mcumgr: unsupported baudrate %u", baud);
		return -EINVAL;
	}

	confirm = dict_get_value(&img->properties, "confirm");
	if (!confirm || !strcmp(confirm, "mcu")) {
		m->confirm = CONFIRM_MCU;
	} else if (!strcmp(confirm, "host")) {
		m->confirm = CONFIRM_HOST;
	} else {
		ERROR("mcumgr: invalid confirm mode '%s'", confirm);
		return -EINVAL;
	}
	return 0;
}

static int install_mcumgr_image(struct img_type *img,
	void __attribute__ ((__unused__)) *data)
{
	struct mcumgr *m;
	struct slot_state slots[2];
	uint8_t newhash[HASH_MAX];
	size_t newhashlen = 0;
	long long total;
	speed_t speed;
	bool pending = false, running = false;
	int ret;

	if (!strlen(img->device)) {
		ERROR("mcumgr: 'device' (UART) not set for %s", img->fname);
		return -EINVAL;
	}

	total = get_output_size(img, true);
	if (total <= 0)
		return -EINVAL;

	m = calloc(1, sizeof(*m));
	if (!m)
		return -ENOMEM;
	m->fd = -1;
	m->total = total;

	ret = parse_properties(img, m, &speed);
	if (ret)
		goto out;

	m->bodycap = m->chunk + CBOR_OVERHEAD;
	m->framescap = smp_serial_encoded_size(SMP_HDR_LEN + m->bodycap);
	m->chunkbuf = malloc(m->chunk);
	m->body = malloc(m->bodycap);
	m->pkt = malloc(SMP_HDR_LEN + m->bodycap);
	m->frames = malloc(m->framescap);
	if (!m->chunkbuf || !m->body || !m->pkt || !m->frames) {
		ret = -ENOMEM;
		goto out;
	}

	m->fd = uart_open(img->device, speed);
	if (m->fd < 0) {
		ret = m->fd;
		goto out;
	}
	/* push and discard what a previous session may have left */
	uart_kick(m);
	rx_drain(m);

	/* 1. check that the MCU answers */
	ret = img_state_read(m, m->timeout_ms, m->retries, slots);
	if (ret) {
		ERROR("MCU on %s does not answer to SMP", img->device);
		goto out;
	}

	/*
	 * 2. upload to the secondary slot. The image is always uploaded: its
	 * hash (MCUboot TLV) is known only once the MCU has it.
	 */
	INFO("mcumgr: uploading %s (%llu bytes) to image %u",
	     img->fname, (unsigned long long)m->total, m->image);
	ret = copyimage(m, img, mcumgr_write);
	if (!ret && m->fill)
		ret = upload_chunk(m);
	if (ret)
		goto out;
	if (m->off != m->total) {
		ERROR("Uploaded %llu bytes, expected %llu",
		      (unsigned long long)m->off, (unsigned long long)m->total);
		ret = -EIO;
		goto out;
	}

	/* 3. get the hash of the uploaded image */
	ret = img_state_read(m, m->timeout_ms, m->retries, slots);
	if (ret)
		goto out;
	if (!slots[1].present || !slots[1].hashlen) {
		ERROR("Uploaded image not found in secondary slot "
		      "(invalid signature / header?)");
		ret = -EFAULT;
		goto out;
	}
	memcpy(newhash, slots[1].hash, slots[1].hashlen);
	newhashlen = slots[1].hashlen;

	if (same_hash(&slots[0], newhash, newhashlen) && slots[0].confirmed) {
		INFO("mcumgr: image already running and confirmed");
		goto out;
	}

	/* 4. mark for test */
	ret = img_state_write(m, newhash, newhashlen, false, slots);
	if (ret)
		goto out;
	pending = true;
	if (!slots[1].pending) {
		ERROR("MCU refused to mark the new image as pending");
		ret = -EFAULT;
		goto out;
	}

	/* 5. reset, MCUboot swaps */
	INFO("mcumgr: resetting MCU for swap");
	ret = os_reset(m);
	if (ret)
		goto out;
	sleep(1);
	rx_flush(m);

	ret = wait_new_image_active(m, newhash, newhashlen, slots);
	if (ret) {
		/* still pending only if the old image is still running */
		pending = same_hash(&slots[1], newhash, newhashlen) &&
			  slots[1].pending;
		goto out;
	}
	pending = false;
	running = true;

	/* 6. confirm */
	if (m->confirm == CONFIRM_HOST) {
		ret = img_state_write(m, newhash, newhashlen, true, slots);
		if (!ret && !slots[0].confirmed)
			ret = -EFAULT;
	} else {
		ret = wait_mcu_confirm(m, slots);
	}
	if (ret)
		goto out;

	INFO("mcumgr: MCU updated and image confirmed");

out:
	if (ret && running) {
		/* new image running in test mode: reset -> MCUboot reverts */
		WARN("mcumgr: resetting MCU to roll back");
		os_reset(m);
	} else if (ret && pending) {
		cancel_pending(m);
	}
	if (m->fd >= 0)
		close(m->fd);
	free(m->chunkbuf);
	free(m->body);
	free(m->pkt);
	free(m->frames);
	free(m);
	return ret;
}

__attribute__((constructor))
static void mcumgr_handler(void)
{
	register_handler("mcumgr", install_mcumgr_image,
			 IMAGE_HANDLER, NULL);
}
