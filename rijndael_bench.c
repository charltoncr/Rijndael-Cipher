/* rijndael_bench.c - benchmark code in rijndael.c.
Author: Ron Charlton 2018-07-29

This file contains a public domain benchmark for rijndael.c. Public domain
is per CC0 1.0; see https://creativecommons.org/publicdomain/zero/1.0/ for 
information.

Rijndael is pronounced 'rain-dal with the "a" in "dal" pronounced as in "pal".

On iBUYPOWER P700 PRO with 3.60 GHz Intel Core i7-3820 and 667 MHz memory and
64-bit Windows 7 SP1:
c:\csource>rijndael_bench
Benchmarking the Rijndael functions implemented in rijndael.c.

blockbits=128  keybits=128:
Set Key         175.91 ns/op
Encrypt         76.81 ns/op             208.29 MB/s
Decrypt         77.17 ns/op             207.32 MB/s

blockbits=128  keybits=192:
Set Key         187.00 ns/op
Encrypt         88.88 ns/op             180.01 MB/s
Decrypt         89.07 ns/op             179.63 MB/s

blockbits=128  keybits=256:
Set Key         226.42 ns/op
Encrypt         103.16 ns/op            155.09 MB/s
Decrypt         103.34 ns/op            154.83 MB/s

blockbits=192  keybits=128:
Set Key         284.69 ns/op
Encrypt         124.27 ns/op            193.13 MB/s
Decrypt         129.35 ns/op            185.54 MB/s

blockbits=192  keybits=192:
Set Key         250.68 ns/op
Encrypt         124.32 ns/op            193.05 MB/s
Decrypt         129.42 ns/op            185.44 MB/s

blockbits=192  keybits=256:
Set Key         317.37 ns/op
Encrypt         141.16 ns/op            170.02 MB/s
Decrypt         146.81 ns/op            163.48 MB/s

blockbits=256  keybits=128:
Set Key         418.14 ns/op
Encrypt         187.18 ns/op            170.95 MB/s
Decrypt         196.73 ns/op            162.66 MB/s

blockbits=256  keybits=192:
Set Key         362.33 ns/op
Encrypt         187.40 ns/op            170.76 MB/s
Decrypt         196.16 ns/op            163.13 MB/s

blockbits=256  keybits=256:
Set Key         398.49 ns/op
Encrypt         187.17 ns/op            170.96 MB/s
Decrypt         198.28 ns/op            161.39 MB/s
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char rcs_id_rijndael_test[] =
		"$Id: rijndael_bench.c 1.36 2020-03-27 09:11:39-05 Ron Exp $";

#include "rijndael.h"

#include "rijndael.c"

#ifdef __cplusplus
extern "C" {
#endif

char progName[] = "rijndael_bench";

#ifndef min
	#define min(a,b) ((a)<(b)?(a):(b))
#endif

static void
usage(FILE *stream, char *message, ...)
{
	va_list args;

	if (stream) {
		if (message && *message) {
			fflush(stdout);
			fprintf(stderr, "%s: ", progName);

			va_start(args, message);
			vfprintf(stream, message, args);
			va_end(args);

			fputc('\n', stream);
		}

		fprintf(stream,
			"%s benchmarks the Rijndael cipher source code in rijndael.c.\n"
			"All block sizes and key sizes are benchmarked.\n"
			"Usage: %s\n"
			"       %s -h\n"
			"Options:\n"
			"  -h shows this help message\n", progName, progName, progName);
	}

	exit(stream == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


#if RAND_MAX < 32767
	#error "RAND_MAX is too small."
#endif

/* 32-bit unsigned PRNG (Microsoft C rand() has 15 significant bits!) */
static uint32_t
rand_uint32(void)
{
	return (uint32_t)rand() << 17 ^
		   (uint32_t)rand() <<  9 ^
		   (uint32_t)rand() >>  3;
}


/* Get n unsigned char pseudorandom values from rand() into buffer pointed to
 * by p.  Returns 0 on success or 1 on argument error.
 */
static int
rand_bytes(void *p, size_t n)
{
	uint32_t m;
	unsigned char *q = p;
	unsigned char *end = q + n;
	size_t bytesLeft;

	if (!q) {
		errno = EINVAL;
		return 1;
	}

	for (; n;) {
		m = rand_uint32();
		bytesLeft = end - q;
		memcpy(q, &m, min(bytesLeft, sizeof(m)));
		if (bytesLeft <= sizeof(m)) {
			break;
		}
		q += sizeof(m);
	}

	return 0;
}


static double
seconds(void)
{
	return (double)clock() / CLOCKS_PER_SEC;
}


/* Benchmark the Rijndael functions implemented in rijndael.c. */
static void
benchmark(void)
{
	static rijn_context ctx;
	static uint8_t key[32];
	static uint8_t PT[32];
	static uint8_t CT[sizeof(PT)];
	static uint8_t IV[sizeof(PT)];
	size_t i, j, loopcount = 5000000;
	double start, dur;
	int keybits, blockbits;

	srand(123456789);
	//srand((unsigned int)time(NULL));
	rand_bytes(PT, sizeof(PT));
	rand_bytes(key, sizeof(key));
	rand_bytes(IV, sizeof(IV));

	printf("Benchmarking the Rijndael functions implemented in rijndael.c.\n");

	for (blockbits = 128; blockbits <= 256; blockbits += 64) {
		size_t size = blockbits / 8;
		for (keybits = 128; keybits <= 256; keybits += 64) {
			printf("\nblockbits=%d  keybits=%d:\n", blockbits, keybits);
			start = seconds();
			for (i = 0; i < loopcount; i++) {
				rijn_set_key(&ctx, key, keybits, blockbits);
			}
			dur = seconds() - start;
			printf("Set Key\t\t%7.0f ns/op\n", dur * 1e9 / loopcount);

			start = seconds();
			for (i = 0; i < loopcount; i++) {
				rijn_encrypt(&ctx, PT, CT);
			}
			dur = seconds() - start;
			printf("ECB Encrypt\t%7.0f ns/op\t\t%.2f MB/s\n",
					dur * 1e9 / loopcount, size * loopcount / 1e6 / dur);

			start = seconds();
			for (i = 0; i < loopcount; i++) {
				rijn_decrypt(&ctx, CT, PT);
			}

			dur = seconds() - start;
			printf("ECB Decrypt\t%7.0f ns/op\t\t%.2f MB/s\n",
					dur * 1e9 / loopcount, size * loopcount / 1e6 / dur);
			dur = seconds() - start;

			for (i = 0; i < loopcount; i++) {
				rijn_cbc_encrypt(&ctx, PT, IV, CT, size);
			}
			printf("CBC Encrypt\t%7.0f ns/op\t\t%.2f MB/s\n",
					dur * 1e9 / loopcount, size * loopcount / 1e6 / dur);

			start = seconds();
			for (i = 0; i < loopcount; i++) {
				rijn_cbc_decrypt(&ctx, CT, IV, PT, size);
			}
			dur = seconds() - start;
			printf("CBC Decrypt\t%7.0f ns/op\t\t%.2f MB/s\n",
					dur * 1e9 / loopcount, size * loopcount / 1e6 / dur);
		}
	}
}


int
main(int argc, char *argv[])
{
	if (argc > 1) {
		usage(stderr, NULL);
	}

	benchmark();

	return EXIT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
