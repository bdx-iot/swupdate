// SPDX-FileCopyrightText: 2026 Joris Offouga <offougajoris@gmail.com>
//
// SPDX-License-Identifier: GPL-2.0-only

/*
 * Tests for the CBOR subset and the serial framing used by the
 * mcumgr handler (handlers/mcumgr_smp.c).
 */

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "handlers/mcumgr_smp.h"

/* ------------------------------------------------------------------ */
/* CBOR encoder, vectors from RFC 8949 appendix A                     */
/* ------------------------------------------------------------------ */

static void check_uint(uint64_t v, const uint8_t *exp, size_t n)
{
	uint8_t buf[16];
	struct smp_cbor_enc e = { .p = buf, .cap = sizeof(buf) };

	smp_cbor_uint(&e, v);
	assert_false(e.err);
	assert_int_equal(e.len, n);
	assert_memory_equal(buf, exp, n);
}

static void test_cbor_encode_uint(void **state)
{
	(void)state;
	check_uint(0, (const uint8_t *)"\x00", 1);
	check_uint(23, (const uint8_t *)"\x17", 1);
	check_uint(24, (const uint8_t *)"\x18\x18", 2);
	check_uint(100, (const uint8_t *)"\x18\x64", 2);
	check_uint(1000, (const uint8_t *)"\x19\x03\xe8", 3);
	check_uint(1000000, (const uint8_t *)"\x1a\x00\x0f\x42\x40", 5);
	check_uint(1000000000000ULL,
		   (const uint8_t *)"\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00", 9);
}

static void test_cbor_encode_types(void **state)
{
	uint8_t buf[32];
	struct smp_cbor_enc e = { .p = buf, .cap = sizeof(buf) };
	/* {"a": h'01020304', "t": true, "f": false} */
	static const uint8_t exp[] = {
		0xa3, 0x61, 'a', 0x44, 1, 2, 3, 4,
		0x61, 't', 0xf5, 0x61, 'f', 0xf4
	};

	(void)state;
	smp_cbor_map(&e, 3);
	smp_cbor_tstr(&e, "a");
	smp_cbor_bstr(&e, "\x01\x02\x03\x04", 4);
	smp_cbor_tstr(&e, "t");
	smp_cbor_bool(&e, true);
	smp_cbor_tstr(&e, "f");
	smp_cbor_bool(&e, false);
	assert_false(e.err);
	assert_int_equal(e.len, sizeof(exp));
	assert_memory_equal(buf, exp, sizeof(exp));
}

static void test_cbor_encode_overflow(void **state)
{
	uint8_t buf[4];
	struct smp_cbor_enc e = { .p = buf, .cap = sizeof(buf) };

	(void)state;
	smp_cbor_tstr(&e, "abc");	/* 4 bytes: fits */
	assert_false(e.err);
	smp_cbor_uint(&e, 1);		/* does not fit */
	assert_true(e.err);
	assert_int_equal(e.len, 4);
}

/* ------------------------------------------------------------------ */
/* CBOR decoder                                                       */
/* ------------------------------------------------------------------ */

/* {"a": 1, "b": [2, 3]} */
static const uint8_t map_def[] = {
	0xa2, 0x61, 'a', 0x01, 0x61, 'b', 0x82, 0x02, 0x03
};

/* {_ "a": 1, "b": [_ 2, 3]}, as encoded by zcbor */
static const uint8_t map_indef[] = {
	0xbf, 0x61, 'a', 0x01, 0x61, 'b', 0x9f, 0x02, 0x03, 0xff, 0xff
};

static void check_map(const uint8_t *m, size_t n)
{
	const uint8_t *end = m + n, *v;
	struct smp_cbor_iter it;
	uint64_t u, items[2];
	int count = 0;

	assert_ptr_equal(smp_cbor_skip(m, end), end);

	v = smp_cbor_map_get(m, end, "a");
	assert_non_null(v);
	assert_true(smp_cbor_get_uint(v, end, &u));
	assert_int_equal(u, 1);

	v = smp_cbor_map_get(m, end, "b");
	assert_non_null(v);
	assert_true(smp_cbor_iter_init(&it, v, end, 4));
	while (smp_cbor_iter_next(&it)) {
		assert_true(count < 2);
		assert_true(smp_cbor_get_uint(it.p, end, &items[count++]));
		it.p = smp_cbor_skip(it.p, end);
	}
	assert_int_equal(count, 2);
	assert_int_equal(items[0], 2);
	assert_int_equal(items[1], 3);

	assert_null(smp_cbor_map_get(m, end, "c"));
	assert_null(smp_cbor_map_get(m, end, "aa"));
}

static void test_cbor_decode_map(void **state)
{
	(void)state;
	check_map(map_def, sizeof(map_def));
	check_map(map_indef, sizeof(map_indef));
}

static void test_cbor_decode_values(void **state)
{
	static const uint8_t bstr[] = { 0x44, 1, 2, 3, 4 };
	static const uint8_t u32[] = { 0x1a, 0x00, 0x0f, 0x42, 0x40 };
	static const uint8_t t = 0xf5, f = 0xf4;
	const uint8_t *d;
	uint64_t u;
	size_t n;
	bool b;

	(void)state;
	assert_true(smp_cbor_get_bstr(bstr, bstr + sizeof(bstr), &d, &n));
	assert_int_equal(n, 4);
	assert_memory_equal(d, "\x01\x02\x03\x04", 4);

	assert_true(smp_cbor_get_uint(u32, u32 + sizeof(u32), &u));
	assert_int_equal(u, 1000000);

	assert_true(smp_cbor_get_bool(&t, &t + 1, &b));
	assert_true(b);
	assert_true(smp_cbor_get_bool(&f, &f + 1, &b));
	assert_false(b);

	/* wrong types */
	assert_false(smp_cbor_get_uint(bstr, bstr + sizeof(bstr), &u));
	assert_false(smp_cbor_get_bstr(u32, u32 + sizeof(u32), &d, &n));
	assert_false(smp_cbor_get_bool(u32, u32 + sizeof(u32), &b));
}

static void test_cbor_decode_truncated(void **state)
{
	size_t i;

	(void)state;
	/* every truncation of a valid item must be rejected */
	for (i = 0; i < sizeof(map_def); i++)
		assert_null(smp_cbor_skip(map_def, map_def + i));
	for (i = 0; i < sizeof(map_indef); i++)
		assert_null(smp_cbor_skip(map_indef, map_indef + i));

	/* string longer than the buffer */
	assert_null(smp_cbor_skip((const uint8_t *)"\x45\x01\x02",
				  (const uint8_t *)"\x45\x01\x02" + 3));
	/* huge array count on a short buffer */
	assert_null(smp_cbor_skip((const uint8_t *)"\x9b\xff\xff\xff\xff\xff\xff\xff\xff",
				  (const uint8_t *)"\x9b\xff\xff\xff\xff\xff\xff\xff\xff" + 9));
}

static void test_cbor_decode_depth(void **state)
{
	uint8_t deep[64];

	(void)state;
	/* 63 nested arrays of one element, then 0: too deep */
	memset(deep, 0x81, sizeof(deep) - 1);
	deep[sizeof(deep) - 1] = 0x00;
	assert_null(smp_cbor_skip(deep, deep + sizeof(deep)));
}

/* ------------------------------------------------------------------ */
/* CRC and serial transport                                           */
/* ------------------------------------------------------------------ */

static void test_crc16(void **state)
{
	(void)state;
	/* CRC-16/XMODEM check value */
	assert_int_equal(smp_crc16((const uint8_t *)"123456789", 9), 0x31c3);
}

/* image state read, seq 0x2a */
static const uint8_t state_read[] = { 0, 0, 0, 1, 0, 1, 0x2a, 0, 0xa0 };

static void test_serial_encode_vector(void **state)
{
	static const char exp[] = "\x06\x09" "AAsAAAABAAEqAKDH+Q==" "\n";
	uint8_t out[64];
	size_t n;

	(void)state;
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	assert_int_equal(n, strlen(exp));
	assert_memory_equal(out, exp, n);
	assert_true(n <= smp_serial_encoded_size(sizeof(state_read)));

	/* too small output buffer */
	assert_int_equal(smp_serial_encode(state_read, sizeof(state_read),
					   out, n - 1), 0);
}

/* Split the encoded frames in lines and feed them to the receiver */
static int feed(struct smp_serial_rx *rx, const uint8_t *buf, size_t n,
		int *frames)
{
	size_t start = 0, i;
	int ret = 0;

	*frames = 0;
	for (i = 0; i < n; i++) {
		if (buf[i] != '\n')
			continue;
		assert_true(i - start + 1 <= SMP_SER_MAX_FRAME);
		if (*frames == 0) {
			assert_int_equal(buf[start], SMP_SER_PKT_START_1);
			assert_int_equal(buf[start + 1], SMP_SER_PKT_START_2);
		} else {
			assert_int_equal(buf[start], SMP_SER_FRAG_START_1);
			assert_int_equal(buf[start + 1], SMP_SER_FRAG_START_2);
		}
		(*frames)++;
		ret = smp_serial_rx_line(rx, buf + start, i - start);
		start = i + 1;
	}
	assert_int_equal(start, n);
	return ret;
}

static void test_serial_roundtrip(void **state)
{
	static struct smp_serial_rx rx;
	uint8_t pkt[600], out[1024];
	size_t sizes[] = { 9, 90, 91, 92, 93, 200, sizeof(pkt) };
	size_t i, k, n;
	int frames;

	(void)state;
	for (i = 0; i < sizeof(pkt); i++)
		pkt[i] = (uint8_t)(i * 7 + 3);

	for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
		n = smp_serial_encode(pkt, sizes[k], out, sizeof(out));
		assert_true(n > 0);
		smp_serial_rx_reset(&rx);
		assert_int_equal(feed(&rx, out, n, &frames), 1);
		assert_int_equal(rx.len, sizes[k]);
		assert_memory_equal(rx.buf, pkt, sizes[k]);
		if (sizes[k] > 100)
			assert_true(frames > 1);
	}
}

static void test_serial_rx_errors(void **state)
{
	static struct smp_serial_rx rx;
	static const char logline[] = "I: Starting bootloader";
	static const char frag[] = "\x04\x14" "AAsA";
	uint8_t out[64];
	size_t n;

	(void)state;
	smp_serial_rx_reset(&rx);

	/* not SMP: ignored */
	assert_int_equal(smp_serial_rx_line(&rx, (const uint8_t *)logline,
					    strlen(logline)), 0);
	/* continuation without start: ignored */
	assert_int_equal(smp_serial_rx_line(&rx, (const uint8_t *)frag,
					    strlen(frag)), 0);

	/* '\r' before '\n' is accepted */
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	out[n - 1] = '\r';
	assert_int_equal(smp_serial_rx_line(&rx, out, n), 1);

	/* corrupted payload: CRC error */
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	out[10] = (out[10] == 'A') ? 'B' : 'A';
	assert_int_equal(smp_serial_rx_line(&rx, out, n - 1), -EBADMSG);

	/* invalid base64 */
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	out[5] = '*';
	assert_int_equal(smp_serial_rx_line(&rx, out, n - 1), -EBADMSG);

	/* truncated base64 (not a multiple of 4) */
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	assert_int_equal(smp_serial_rx_line(&rx, out, n - 2), -EBADMSG);

	/* a new packet start resets a partial one */
	n = smp_serial_encode(state_read, sizeof(state_read), out, sizeof(out));
	assert_int_equal(smp_serial_rx_line(&rx, out, n - 1), 1);
	assert_int_equal(rx.len, sizeof(state_read));
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cbor_encode_uint),
		cmocka_unit_test(test_cbor_encode_types),
		cmocka_unit_test(test_cbor_encode_overflow),
		cmocka_unit_test(test_cbor_decode_map),
		cmocka_unit_test(test_cbor_decode_values),
		cmocka_unit_test(test_cbor_decode_truncated),
		cmocka_unit_test(test_cbor_decode_depth),
		cmocka_unit_test(test_crc16),
		cmocka_unit_test(test_serial_encode_vector),
		cmocka_unit_test(test_serial_roundtrip),
		cmocka_unit_test(test_serial_rx_errors),
	};

	return cmocka_run_group_tests_name("mcumgr_smp", tests, NULL, NULL);
}
