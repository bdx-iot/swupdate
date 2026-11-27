/*
 * (C) Copyright 2026
 * Joris Offouga, offougajoris@gmail.com.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

/*
 * Encoding helpers for the MCUmgr SMP protocol, used by the mcumgr handler:
 * - the small CBOR subset used by SMP
 * - the SMP serial transport (Zephyr "SMP over console" framing)
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* SMP header */
#define SMP_HDR_LEN		8
#define SMP_OP_READ		0
#define SMP_OP_WRITE		2

#define SMP_GRP_OS		0
#define SMP_GRP_IMG		1

#define SMP_ID_OS_RESET		5
#define SMP_ID_IMG_STATE	0
#define SMP_ID_IMG_UPLOAD	1
#define SMP_ID_IMG_ERASE	5

/* Serial transport */
#define SMP_SER_PKT_START_1	0x06
#define SMP_SER_PKT_START_2	0x09
#define SMP_SER_FRAG_START_1	0x04
#define SMP_SER_FRAG_START_2	0x14
#define SMP_SER_MAX_FRAME	127	/* marker + base64 + '\n' */
#define SMP_SER_B64_PER_FRAME	(SMP_SER_MAX_FRAME - 3)	/* multiple of 4 */
#define SMP_SER_RX_MAX		2048

/* CBOR encoder: on overflow, err is set and the buffer is not modified */
struct smp_cbor_enc {
	uint8_t *p;
	size_t len;
	size_t cap;
	bool err;
};

void smp_cbor_uint(struct smp_cbor_enc *e, uint64_t v);
void smp_cbor_bool(struct smp_cbor_enc *e, bool b);
void smp_cbor_tstr(struct smp_cbor_enc *e, const char *s);
void smp_cbor_bstr(struct smp_cbor_enc *e, const void *d, size_t n);
void smp_cbor_map(struct smp_cbor_enc *e, size_t pairs);

/*
 * CBOR decoder. All functions check the bounds and return NULL / false
 * on malformed or truncated input. Definite and indefinite length arrays
 * and maps are supported (zcbor uses indefinite ones).
 */
const uint8_t *smp_cbor_skip(const uint8_t *p, const uint8_t *end);
const uint8_t *smp_cbor_map_get(const uint8_t *map, const uint8_t *end,
				const char *key);
bool smp_cbor_get_uint(const uint8_t *p, const uint8_t *end, uint64_t *v);
bool smp_cbor_get_bool(const uint8_t *p, const uint8_t *end, bool *b);
bool smp_cbor_get_bstr(const uint8_t *p, const uint8_t *end,
		       const uint8_t **d, size_t *n);

/* Iterate over the items of an array (major 4) or a map (major 5) */
struct smp_cbor_iter {
	const uint8_t *p;	/* next item, advance it with smp_cbor_skip() */
	const uint8_t *end;
	bool indef;
	uint64_t left;
};

bool smp_cbor_iter_init(struct smp_cbor_iter *it, const uint8_t *p,
			const uint8_t *end, uint8_t major);
bool smp_cbor_iter_next(struct smp_cbor_iter *it);

/* CRC-16/XMODEM, as used by the SMP serial transport */
uint16_t smp_crc16(const uint8_t *d, size_t n);

/*
 * Serial transport, transmit: encode one SMP packet (header + CBOR) into
 * frames ready to be written to the UART. Returns the number of bytes
 * written to out, 0 if out is too small.
 */
size_t smp_serial_encoded_size(size_t pktlen);
size_t smp_serial_encode(const uint8_t *pkt, size_t pktlen,
			 uint8_t *out, size_t cap);

/* Serial transport, receive: feed it the received lines (without '\n') */
struct smp_serial_rx {
	uint8_t buf[SMP_SER_RX_MAX];
	size_t len;
	bool in_pkt;
};

void smp_serial_rx_reset(struct smp_serial_rx *rx);

/*
 * Returns 1 when a complete packet is in rx->buf / rx->len (SMP header +
 * CBOR, length and CRC removed), 0 if the line is not an SMP frame or more
 * frames are needed, -EBADMSG if a packet was dropped (bad base64 or CRC).
 */
int smp_serial_rx_line(struct smp_serial_rx *rx, const uint8_t *line,
		       size_t n);
