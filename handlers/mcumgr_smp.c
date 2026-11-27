/*
 * (C) Copyright 2026
 * Joris Offouga, offougajoris@gmail.com.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

/*
 * Encoding helpers for the MCUmgr SMP protocol: CBOR subset and serial
 * transport framing. No I/O here, see mcumgr_handler.c.
 */

#include <errno.h>
#include <string.h>

#include "mcumgr_smp.h"

#define CBOR_BREAK		0xff
#define CBOR_FALSE		0xf4
#define CBOR_TRUE		0xf5
#define CBOR_MAX_DEPTH		16

/* ------------------------------------------------------------------ */
/* CBOR encoder                                                       */
/* ------------------------------------------------------------------ */

static void cbor_put(struct smp_cbor_enc *e, const void *d, size_t n)
{
	if (e->err || n > e->cap - e->len) {
		e->err = true;
		return;
	}
	memcpy(e->p + e->len, d, n);
	e->len += n;
}

static void cbor_head(struct smp_cbor_enc *e, uint8_t major, uint64_t v)
{
	uint8_t b[9];
	size_t n, i;

	major <<= 5;
	if (v < 24) {
		b[0] = major | v;
		n = 1;
	} else if (v <= UINT8_MAX) {
		b[0] = major | 24;
		n = 2;
	} else if (v <= UINT16_MAX) {
		b[0] = major | 25;
		n = 3;
	} else if (v <= UINT32_MAX) {
		b[0] = major | 26;
		n = 5;
	} else {
		b[0] = major | 27;
		n = 9;
	}
	for (i = 1; i < n; i++)
		b[i] = v >> (8 * (n - 1 - i));
	cbor_put(e, b, n);
}

void smp_cbor_uint(struct smp_cbor_enc *e, uint64_t v)
{
	cbor_head(e, 0, v);
}

void smp_cbor_bool(struct smp_cbor_enc *e, bool b)
{
	uint8_t v = b ? CBOR_TRUE : CBOR_FALSE;

	cbor_put(e, &v, 1);
}

void smp_cbor_bstr(struct smp_cbor_enc *e, const void *d, size_t n)
{
	cbor_head(e, 2, n);
	cbor_put(e, d, n);
}

void smp_cbor_tstr(struct smp_cbor_enc *e, const char *s)
{
	size_t n = strlen(s);

	cbor_head(e, 3, n);
	cbor_put(e, s, n);
}

void smp_cbor_map(struct smp_cbor_enc *e, size_t pairs)
{
	cbor_head(e, 5, pairs);
}

/* ------------------------------------------------------------------ */
/* CBOR decoder                                                       */
/* ------------------------------------------------------------------ */

static const uint8_t *cbor_read_head(const uint8_t *p, const uint8_t *end,
				     uint8_t *major, uint64_t *val,
				     bool *indef)
{
	uint8_t ai;

	if (!p || p >= end)
		return NULL;
	*major = *p >> 5;
	ai = *p & 0x1f;
	p++;
	*indef = false;
	*val = 0;

	if (ai < 24) {
		*val = ai;
	} else if (ai <= 27) {
		size_t n = 1u << (ai - 24);

		if ((size_t)(end - p) < n)
			return NULL;
		while (n--)
			*val = (*val << 8) | *p++;
	} else if (ai == 31 && *major >= 2 && *major <= 5) {
		*indef = true;
	} else {
		return NULL;
	}
	return p;
}

static const uint8_t *cbor_skip(const uint8_t *p, const uint8_t *end,
				int depth)
{
	uint8_t major;
	uint64_t val, items, i;
	bool indef;

	if (depth > CBOR_MAX_DEPTH)
		return NULL;
	p = cbor_read_head(p, end, &major, &val, &indef);
	if (!p)
		return NULL;

	switch (major) {
	case 0:
	case 1:
	case 7:
		return p;
	case 2:
	case 3:
		/* indefinite strings are not used by SMP */
		if (indef || val > (uint64_t)(end - p))
			return NULL;
		return p + val;
	case 4:
	case 5:
		if (indef) {
			while (p && p < end && *p != CBOR_BREAK)
				p = cbor_skip(p, end, depth + 1);
			return (p && p < end) ? p + 1 : NULL;
		}
		if (val > (uint64_t)(end - p))	/* at least 1 byte per item */
			return NULL;
		items = (major == 5) ? val * 2 : val;
		for (i = 0; i < items && p; i++)
			p = cbor_skip(p, end, depth + 1);
		return p;
	case 6:
		return cbor_skip(p, end, depth + 1);
	}
	return NULL;
}

const uint8_t *smp_cbor_skip(const uint8_t *p, const uint8_t *end)
{
	return cbor_skip(p, end, 0);
}

bool smp_cbor_iter_init(struct smp_cbor_iter *it, const uint8_t *p,
			const uint8_t *end, uint8_t major)
{
	uint8_t m;
	uint64_t val;

	it->end = end;
	it->p = cbor_read_head(p, end, &m, &val, &it->indef);
	if (!it->p || m != major)
		return false;
	it->left = (major == 5) ? val * 2 : val;
	return true;
}

bool smp_cbor_iter_next(struct smp_cbor_iter *it)
{
	if (!it->p || it->p >= it->end)
		return false;
	if (it->indef)
		return *it->p != CBOR_BREAK;
	if (!it->left)
		return false;
	it->left--;
	return true;
}

const uint8_t *smp_cbor_map_get(const uint8_t *map, const uint8_t *end,
				const char *key)
{
	struct smp_cbor_iter it;
	size_t klen = strlen(key);

	if (!smp_cbor_iter_init(&it, map, end, 5))
		return NULL;

	while (smp_cbor_iter_next(&it)) {
		uint8_t major;
		uint64_t val;
		bool indef;
		const uint8_t *k = cbor_read_head(it.p, end, &major, &val,
						  &indef);

		if (!k)
			return NULL;
		if (major == 3 && val == klen && (size_t)(end - k) >= klen &&
		    !memcmp(k, key, klen))
			return k + klen;

		/* skip key and value */
		it.p = smp_cbor_skip(it.p, end);
		if (!it.indef) {
			if (!it.left)
				return NULL;
			it.left--;
		}
		it.p = smp_cbor_skip(it.p, end);
	}
	return NULL;
}

bool smp_cbor_get_uint(const uint8_t *p, const uint8_t *end, uint64_t *v)
{
	uint8_t major;
	bool indef;

	p = cbor_read_head(p, end, &major, v, &indef);
	return p && major == 0;
}

bool smp_cbor_get_bool(const uint8_t *p, const uint8_t *end, bool *b)
{
	if (!p || p >= end)
		return false;
	if (*p == CBOR_TRUE) {
		*b = true;
		return true;
	}
	if (*p == CBOR_FALSE) {
		*b = false;
		return true;
	}
	return false;
}

bool smp_cbor_get_bstr(const uint8_t *p, const uint8_t *end,
		       const uint8_t **d, size_t *n)
{
	uint8_t major;
	uint64_t val;
	bool indef;

	p = cbor_read_head(p, end, &major, &val, &indef);
	if (!p || major != 2 || indef || val > (uint64_t)(end - p))
		return false;
	*d = p;
	*n = val;
	return true;
}

/* ------------------------------------------------------------------ */
/* CRC-16/XMODEM and base64                                           */
/* ------------------------------------------------------------------ */

uint16_t smp_crc16(const uint8_t *d, size_t n)
{
	uint16_t crc = 0;
	int i;

	while (n--) {
		crc ^= (uint16_t)(*d++) << 8;
		for (i = 0; i < 8; i++)
			crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
	}
	return crc;
}

static const char b64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(uint8_t c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/* Returns the decoded length, -1 on invalid input or overflow */
static int b64_decode(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
	size_t i, o = 0;
	uint32_t acc = 0;
	int bits = 0, v;

	if (n % 4)
		return -1;
	for (i = 0; i < n; i++) {
		if (in[i] == '=') {
			/* padding only at the end */
			if (i < n - 2 || (i == n - 2 && in[n - 1] != '='))
				return -1;
			break;
		}
		v = b64_val(in[i]);
		if (v < 0)
			return -1;
		acc = (acc << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= cap)
				return -1;
			out[o++] = (acc >> bits) & 0xff;
		}
	}
	return o;
}

/* ------------------------------------------------------------------ */
/* Serial transport                                                   */
/* ------------------------------------------------------------------ */

/*
 * A packet is sent as: base64([len BE16][SMP packet][CRC16 BE16]), where
 * len counts the SMP packet and the CRC. The base64 text is split in
 * frames of at most SMP_SER_MAX_FRAME bytes: the first one starts with
 * 0x06 0x09, the next ones with 0x04 0x14, each one ends with '\n'.
 */

static size_t raw_len(size_t pktlen)
{
	return 2 + pktlen + 2;
}

size_t smp_serial_encoded_size(size_t pktlen)
{
	size_t b64 = (raw_len(pktlen) + 2) / 3 * 4;
	size_t frames = (b64 + SMP_SER_B64_PER_FRAME - 1) / SMP_SER_B64_PER_FRAME;

	return b64 + 3 * frames;
}

/* byte i of [len][pkt][crc], without building this buffer */
static uint8_t raw_byte(const uint8_t *pkt, size_t pktlen, uint16_t crc,
			size_t i)
{
	if (i == 0)
		return (pktlen + 2) >> 8;
	if (i == 1)
		return (pktlen + 2) & 0xff;
	if (i < 2 + pktlen)
		return pkt[i - 2];
	return (i == 2 + pktlen) ? crc >> 8 : crc & 0xff;
}

size_t smp_serial_encode(const uint8_t *pkt, size_t pktlen,
			 uint8_t *out, size_t cap)
{
	size_t n = raw_len(pktlen);
	uint16_t crc = smp_crc16(pkt, pktlen);
	size_t i, o = 0, in_frame = 0;

	if (pktlen > UINT16_MAX - 2 || cap < smp_serial_encoded_size(pktlen))
		return 0;

	for (i = 0; i < n; i += 3) {
		uint32_t v = raw_byte(pkt, pktlen, crc, i) << 16;
		char q[4];
		int k;

		if (i + 1 < n)
			v |= raw_byte(pkt, pktlen, crc, i + 1) << 8;
		if (i + 2 < n)
			v |= raw_byte(pkt, pktlen, crc, i + 2);
		q[0] = b64tab[(v >> 18) & 0x3f];
		q[1] = b64tab[(v >> 12) & 0x3f];
		q[2] = (i + 1 < n) ? b64tab[(v >> 6) & 0x3f] : '=';
		q[3] = (i + 2 < n) ? b64tab[v & 0x3f] : '=';

		for (k = 0; k < 4; k++) {
			if (in_frame == 0) {
				bool first = (o == 0);

				out[o++] = first ? SMP_SER_PKT_START_1 :
						   SMP_SER_FRAG_START_1;
				out[o++] = first ? SMP_SER_PKT_START_2 :
						   SMP_SER_FRAG_START_2;
			}
			out[o++] = q[k];
			if (++in_frame == SMP_SER_B64_PER_FRAME) {
				out[o++] = '\n';
				in_frame = 0;
			}
		}
	}
	if (in_frame)
		out[o++] = '\n';
	return o;
}

void smp_serial_rx_reset(struct smp_serial_rx *rx)
{
	rx->len = 0;
	rx->in_pkt = false;
}

int smp_serial_rx_line(struct smp_serial_rx *rx, const uint8_t *line,
		       size_t n)
{
	size_t pktlen;
	int d;

	if (n && line[n - 1] == '\r')
		n--;
	if (n < 2)
		return 0;

	if (line[0] == SMP_SER_PKT_START_1 && line[1] == SMP_SER_PKT_START_2) {
		smp_serial_rx_reset(rx);
		rx->in_pkt = true;
	} else if (line[0] != SMP_SER_FRAG_START_1 ||
		   line[1] != SMP_SER_FRAG_START_2 || !rx->in_pkt) {
		/* not an SMP frame (e.g. boot log): ignore */
		return 0;
	}

	d = b64_decode(line + 2, n - 2, rx->buf + rx->len,
		       sizeof(rx->buf) - rx->len);
	if (d < 0) {
		smp_serial_rx_reset(rx);
		return -EBADMSG;
	}
	rx->len += d;
	if (rx->len < 2)
		return 0;

	pktlen = (rx->buf[0] << 8) | rx->buf[1];	/* SMP packet + CRC */
	if (rx->len < pktlen + 2)
		return 0;

	rx->in_pkt = false;
	/* the CRC computed over the data and the CRC itself is 0 */
	if (pktlen < SMP_HDR_LEN + 2 || rx->len != pktlen + 2 ||
	    smp_crc16(rx->buf + 2, pktlen) != 0) {
		rx->len = 0;
		return -EBADMSG;
	}
	memmove(rx->buf, rx->buf + 2, pktlen - 2);
	rx->len = pktlen - 2;
	return 1;
}
