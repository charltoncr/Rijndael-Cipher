/* This file contains public domain test routines for rijndael.c. Public domain
 * is per CC0 1.0; see https://creativecommons.org/publicdomain/zero/1.0/ for
 * information.
 *
 * Rijndael is pronounced 'rain-dal with the "a" in "dal" pronounced as in "pal".
 *
 * Runtime for all ECB blocksizes and keysizes: 10.1 seconds.
 * Runtime for all CBC blocksizes and keysizes: 13.0 seconds.
 * Both on iBUYPOWER P700 PRO with 3.60 GHz Intel Core i7-3820 and 667 MHz
 * memory.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char rcs_id_rijndael_test[] =
		"$Id: rijndael_test.c 1.43 2020-03-26 13:16:57-05 Ron Exp $";

#include "rijndael.h"

#ifndef min
	#define min(a, b) (a) < (b) ? (a) : (b)
#endif

void printValue( char *label, uint8_t *value, int len, FILE *out );

#define TEST
#include "rijndael.c"
#undef TEST

#ifdef __cplusplus
extern "C" {
#endif


/*
 * test_hexdigit() and test_readhex() are public domain, and are by
 * Markku-Juhani O. Saarinen <mjos@iki.fi>, 19-Nov-2011.
 * Read a hex string and convert to binary; return byte length or -1 on error.
 */
static int
test_hexdigit( char ch )
{
	if ( ch >= '0' && ch <= '9' )
		return	ch - '0';
	if ( ch >= 'A' && ch <= 'F' )
		return	ch - 'A' + 10;
	if ( ch >= 'a' && ch <= 'f' )
		return	ch - 'a' + 10;
	return -1;
}


int
test_readhex( uint8_t *buf, const unsigned char *str, int maxbytes )
{
	int i, h, l;

	for ( i = 0; i < maxbytes; i++ )
	{
		h = test_hexdigit( str[2 * i] );
		if ( h < 0 )
			return i;
		l = test_hexdigit( str[2 * i + 1] );
		if ( l < 0 )
			return i;
		buf[i] = ( h << 4 ) + l;
	}

	return i;
}


/* The following code is by Ron Charlton 2018-01-30. */

char progName[] = "rijndael_test";

static void
usage( FILE *stream, char *message, ... )
{
	va_list args;

	if ( stream )
	{
		if ( message && *message )
		{
			fflush( stdout );
			fprintf( stderr, "%s: ", progName );

			va_start( args, message );
			vfprintf( stream, message, args );
			va_end( args );

			fputc( '\n', stream );
		}

		fprintf(stream,
			"%s validates Rijndael cipher source code in rijndael.c.\n"
			"Usage: %s [-ec[V]]\n"
			"       %s -h|-t\n"
			"Options:\n"
			"  -e test Electronic CodeBook (ECB) mode\n"
			"  -c test Cipher Block Chaining (CBC) mode\n"
			"  -t show timing speeds for CBC mode\n"
			"  -V write verbose output to appropriately named files\n"
			"  -h shows this help message\n"
			"If no option is supplied, a short, random-data test will be run "
			"using all\n"
			"Rijndael functions.\n", progName, progName, progName );
	}

	exit( stream == stderr ? EXIT_FAILURE : EXIT_SUCCESS );
}


#if RAND_MAX < 32767
	#error "RAND_MAX is too small."
#endif

/* 32-bit unsigned PRNG (Microsoft C rand() has 15 significant bits!) */
static uint32_t
rand_uint32( void )
{
	return ( uint32_t )rand() << 17 ^
		   ( uint32_t )rand() <<  9 ^
		   ( uint32_t )rand() >>  3;
}


/* Get n unsigned char pseudorandom values from rand() into buffer pointed to
 * by p.  Returns 0 on success or 1 on argument error.
 */
static int
rand_bytes( void *p, size_t n )
{
	uint32_t m;
	unsigned char *q = p;
	unsigned char *end = q + n;
	size_t bytesLeft;

	if ( !q )
	{
		errno = EINVAL;
		return 1;
	}

	for ( ; n; )
	{
		m = rand_uint32();
		bytesLeft = end - q;
		memcpy( q, &m, min( bytesLeft, sizeof( m ) ) );
		if ( bytesLeft <= sizeof( m ) )
		{
			break;
		}
		q += sizeof( m );
	}

	return 0;
}


void
printValue( char *label, uint8_t *value, int len, FILE *out )
{
	int i;

	fprintf( out, "%s=", label );

	for ( i = 0; i < len; i++)
	{
		fprintf( out, "%02X", value[i] );
	}

	fprintf( out, "\n" );
}


double
seconds( void )
{
	return ( double )clock() / CLOCKS_PER_SEC;
}


/* Brief test using all of the Rijndael functions implemented in rijndael.c. */
static void
brief_test( int time_brief )
{
	int j;
	int blockbits, keybits;
	static rijn_context ctx;
	static uint8_t key[32];
	static uint8_t IV[32], IV_DEC[sizeof( IV )];
	static uint8_t PT[32 * 480000];	/* integer multiple of 16, 24 & 32 */
	static uint8_t CT[sizeof( PT )];
	static uint8_t result[sizeof( PT )];
	size_t i, chunkcount, chunkbytes, blocklen, blockbytes;
	double start;

	printf( "Rijndael Cipher Block Chaining (CBC mode) %ld-byte Random "
			"Data Test:\n", (long) sizeof( PT ) );
	fflush( stdout );

	srand( ( unsigned int )time( NULL ) );
	rand_bytes( PT, sizeof( PT ) );
	rand_bytes( IV, sizeof( IV ) );
	memcpy( IV_DEC, IV, sizeof( IV_DEC ) );
	rand_bytes( key, sizeof( key ) );

	chunkcount = 2;

	for ( blockbits = 128; blockbits <= 256; blockbits += 64 )
	{
		for ( keybits = 128; keybits <= 256; keybits += 64 )
		{
			if ( time_brief ) {
				printf("blockbits=%d keybits=%d ", blockbits, keybits);
			}
			blockbytes = blockbits / 8;

			chunkbytes = blockbytes * chunkcount;

			rijn_set_key( &ctx, key, keybits, blockbits );

			memset(CT, 0, sizeof(CT));
			memset(result, 0, sizeof(result));

			start = seconds();
			for ( i = 0; i < sizeof( PT ); i += chunkbytes )
			{
				rijn_cbc_encrypt( &ctx, IV, PT + i, CT + i, chunkbytes );
			}
			if ( time_brief ) {
				printf("cbc_encrypt: %.0f MB/s  ", sizeof(PT) / 1e6 /
						(seconds() - start));
			}

			start = seconds();
			for ( i = 0; i < sizeof( CT ); i += chunkbytes )
			{
				rijn_cbc_decrypt( &ctx, IV_DEC, CT + i, result + i, chunkbytes );
			}
			if ( time_brief ) {
				printf("cbc_decrypt: %.0f MB/s\n", sizeof(CT) / 1e6 /
						(seconds() - start));
			}
			if ( memcmp( PT, result, blockbytes ) )
			{
				printf( "\nFor block size = %3d, key size = %3d bits: failed!\n",
				blockbits, keybits );
				exit( EXIT_FAILURE );
			}
		}
	}

	printf("passed.\n" );
}


int
main( int argc, char *argv[] )
{
	int verbose = 0;
	int test_ecb = 0;
	int test_cbc = 0;
	int test_brief = 1;
	int time_brief = 0;

	/* find leading options */
	while ( --argc > 0 && **++argv == '-' )
	{
		unsigned char *s = (unsigned char *)*argv;

		if ( !s[1] ) break;	/* a lone "-" stops options scanning */

		while ( *++s )
		{
			switch ( *s )
			{
			case 'c':
				test_cbc = 1;
				break;
			case 'e':
				test_ecb = 1;
				break;
			case 't':
				time_brief = 1;
				break;
			case 'V':
				verbose = 1;
				break;
			case 'h':
			case 'H':
			case '?':
			case '-':	/* when "--help" or similar is typed */
				usage( stdout, NULL );
				/* not reached */
				break;
			default:
				usage( stderr, isprint( *s ) ? "Unknown option -%c" :
						"Unknown option \\x%x", *s );
				/* not reached */
				break;
			}
		}
	}
	if ( argc == 0 ) ++argv;	/* Required when only options are given. */

	if ( verbose && !test_ecb && !test_cbc ) {
		usage(stderr,
				"Option -V applies only with option -e, option -c, or both.");
	}

	if ( test_ecb )
	{
		ecb_test( verbose );
		test_brief = 0;
	}

	if ( test_cbc )
	{
		cbc_test( verbose );
		test_brief = 0;
	}

	if ( test_brief )
	{
		brief_test( time_brief );
		printf( "\n\"%s -h\" for help on more thorough tests.\n", progName );
	}

	return (0);
}

#ifdef __cplusplus
}
#endif
