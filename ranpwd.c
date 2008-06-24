/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 1994-2008 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *   Boston MA 02110-1301, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * ranpwd.c: Generate random passwords using the Linux kernel-based true
 *           random number generator (if available.)
 */

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

static int ran_fd = 0;		/* /dev/(u)random file descriptor if avail. */
static int secure_source = 0;	/* 1 if we should use /dev/random */

const char *program;

enum extended_options {
  OPT_UPPER = 256,
  OPT_LOWER,
  OPT_ASCII,
};

static const char *short_options = "aluxXdobALUimgGMschV";
#ifdef HAVE_GETOPT_LONG
const struct option long_options[] = {
  { "ascii",            0, 0, OPT_ASCII },
  { "alphanum",		0, 0, 'a' },
  { "lc-alphanum",	0, 0, 'l' },
  { "uc-alphanum",	0, 0, 'u' },
  { "hexadecimal",	0, 0, 'x' },
  { "decimal",		0, 0, 'd' },
  { "octal",		0, 0, 'o' },
  { "binary",		0, 0, 'b' },
  { "alpha",		0, 0, 'A' },
  { "lc-alpha",		0, 0, 'L' },
  { "uc-alpha",		0, 0, 'U' },
  { "upper",		0, 0, OPT_UPPER },
  { "lower",		0, 0, OPT_LOWER },
  { "ip",               0, 0, 'i' },
  { "mac-address",      0, 0, 'm' },
  { "guid",             0, 0, 'g' },
  { "uuid",             0, 0, 'g' },
  { "uc-guid",          0, 0, 'G' },
  { "uc-uuid",          0, 0, 'G' },
  { "secure",           0, 0, 's' },
  { "c",		0, 0, 'c' },
  { "help",             0, 0, 'h' },
  { "version",          0, 0, 'V' },
  { 0, 0, 0, 0 }
};
# define LO(X) X
#else
# define getopt_long(C,V,O,L,I) getopt(C,V,O)
# define LO(X)
#endif

static void usage(int err)
{
  fprintf(stderr,
	  "%s %s\n"
	  "Usage: %s [options] [length]\n"
	  LO("  --ascii              " "      Any ASCII characters\n")
	  LO("  --alphanum           ")"  -a  Alphanumeric\n"
	  LO("  --alphanum --lower   ")"  -l  Lower case alphanumeric\n"
	  LO("  --alphanum --upper   ")"  -u  Upper case alphanumeric\n"
	  LO("  --alpha              ")"  -A  Alphabetic\n"
	  LO("  --alpha --lower      ")"  -L  Lower case alphabetic\n"
	  LO("  --alpha --upper      ")"  -U  Upper case alphabetic\n"
	  LO("  --decimal            ")"  -d  Decimal number\n"
	  LO("  --hexadecimal        ")"  -x  Lower case hexadecimal\n"
	  LO("  --hexadecimal --upper")"  -X  Upper case hexadecimal\n"
	  LO("  --octal              ")"  -o  Octal number\n"
	  LO("  --binary             ")"  -b  Binary number\n"
	  LO("  --c                  ")"  -c  C language constant\n"
	  LO("  --uuid               ")"  -g  UUID/GUID\n"
	  LO("  --uuid --upper       ")"  -G  Upper case UUID/GUID\n"
	  LO("  --secure             ")"  -s  Slower but more secure\n"
	  LO("  --help               ")"  -h  Show this message\n"
	  LO("  --version            ")"  -v  Display program version\n"
	  , PACKAGE_NAME, PACKAGE_VERSION, program);
  exit(err);
}

/*
 * setrandom(): Attempt to open /dev/(u)random if available, otherwise call
 *              srand()
 */
static void setrandom(void)
{
  time_t t;
  pid_t pid;

  if ( ran_fd <= 0 )
    {
      ran_fd = open(secure_source ? "/dev/random" : "/dev/urandom", O_RDONLY);

      if ( ran_fd <= 0 )
	{
	  if ( secure_source )
	    {
	      fprintf(stderr, "%s: cannot open /dev/random\n", program);
	      exit(1);
	    }
	  else
	    fprintf(stderr, "%s: warning: cannot open /dev/urandom\n", program);
	  time(&t);
	  pid = getpid();
	  srand(t^pid);		/* As secure as we can get... */
	}
    }
}

/*
 * getrandom(): Get random bytes
 */
static int getrandom(unsigned char *cbuf, size_t nbytes)
{
  int i;

  if ( ran_fd )
    {
      while( nbytes )
	{
	  i = read(ran_fd, cbuf, nbytes);
	  if ( i < 0 )
	    return i;
	  nbytes -= i;
	  cbuf += nbytes;
	}
    }
  else
    {
      while ( nbytes-- )
	*(cbuf++) = (unsigned char) rand();
    }  

  return 0;
}

/*
 * cputc():
 *
 * putchar(), with option to escape characters that have to be escaped in C
 */
static void cputc(int ch, int esc) {
  if ( esc ) {
    switch ( ch ) {
    case '\"': case '\\':
    case '\'':
      putchar('\\');
    default:
      break;
    }
  }
  putchar(ch);
}

enum output_type {
  ty_ascii, ty_lascii, ty_uascii,
  ty_anum, ty_lcase, ty_ucase,
  ty_alpha, ty_alcase, ty_aucase,
  ty_hex, ty_uhex,
  ty_ip,
  ty_mac, ty_umac,
  ty_uuid, ty_uuuid,
  ty_dec, ty_oct, ty_binary
};

static void output_random(enum output_type type, int nchar, int decor)
{
  int i;
  unsigned char ch;
  int ichar = nchar;

  while (nchar) {
    switch (type)
      {
      case ty_ascii:
	getrandom(&ch, 1);
	ch &= 0x7f;
	if ( ch >= 0x21 && ch <= 0x7e ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_lascii:
	getrandom(&ch, 1);
	ch &= 0x7f;
	if (ch >= 0x21 && ch <= 0x7e && !(ch >= 'A' && ch <= 'Z')) {
	  cputc(ch,decor); nchar--;
	}
	break;
	
      case ty_uascii:
	getrandom(&ch, 1);
	ch &= 0x7f;
	if (ch >= 0x21 && ch <= 0x7e && !(ch >= 'a' && ch <= 'z')) {
	  cputc(ch,decor); nchar--;
	}
	break;
	
      case ty_anum:
	getrandom(&ch, 1);
	ch &= 0x7f;
	if ( isalnum(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_lcase:
	getrandom(&ch, 1);
	ch &= 0x5f;
	ch |= 0x20;
	if ( isalnum(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_ucase:
	getrandom(&ch, 1);
	ch &= 0x5f;
	ch |= ( ch < 0x40 ? 0x20 : 0x00 );
	if ( isalnum(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_alpha:
	getrandom(&ch, 1);
	ch &= 0x3f;
	ch |= 0x40;
	if ( isalpha(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_alcase:
	getrandom(&ch, 1);
	ch &= 0x1f;
	ch |= 0x60;
	if ( isalpha(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_aucase:
	getrandom(&ch, 1);
	ch &= 0x1f;
	ch |= 0x40;
	if ( isalpha(ch) ) { cputc(ch,decor); nchar--; }
	break;
	
      case ty_hex:
	getrandom(&ch, 1);
	if ( nchar == 1 ) { printf("%01x", ch & 0x0f); nchar--; }
	else { printf("%02x", ch); nchar -= 2; }
	break;
	
      case ty_uhex:
	getrandom(&ch, 1);
	if ( nchar == 1 ) { printf("%01X", ch & 0x0f); nchar--; }
	else { printf("%02X", ch); nchar -= 2; }
	break;
	
      case ty_dec:
	getrandom(&ch, 1);
	if ( decor && nchar > 1 && ch < 200 ) {
	  ch %= 100;
	  nchar -= 2;
	  if ( ch > 0 || !nchar ) {
	    printf("%d", ch);
	    decor = 0;
	  }
	} else if ( nchar == 1 && ch < 250 ) {
	  printf("%01d", ch % 10); nchar--;
	} else if ( ch < 200 ) { printf("%02d", ch % 100); nchar -= 2; }
	break;
	
      case ty_oct:
	getrandom(&ch, 1);
	if ( nchar == 1 ) { printf("%01o", ch & 007); nchar--; }
	else { printf("%02o", ch & 077); nchar -= 2; }
	break;
	
      case ty_binary:
	getrandom(&ch, 1);
	i = (nchar < 8) ? nchar : 8;
	nchar -= i;
	while ( i-- ) {
	  putchar((ch & 1) + '0');
	  ch >>= 1;
	}
	break;

      case ty_ip:
	do {
	  getrandom(&ch, 1);
	} while (nchar == ichar && (ch-1U) >= 254);
	printf("%s%u", (nchar == ichar) ? "" : ".", ch);
	nchar--;
	break;

      case ty_mac:
      case ty_umac:
	getrandom(&ch, 1);
	if (nchar == ichar) {
	  ch &= ~0x01;
	  ch |= 0x02;
	} else {
	  putchar(':');
	}

	printf(type == ty_umac ? "%02X" : "%02x", ch);
	nchar--;
	break;

      case ty_uuid:
      case ty_uuuid:
	getrandom(&ch, 1);
	switch (ichar-nchar) {
	case 4:
	  putchar('-');
	  break;
	case 6:
	  ch = (ch & 0x0f) | 0x40; /* Version number */
	  putchar('-');
	  break;
	case 8:
	  ch = (ch & 0x3f) | 0x80; /* By spec */
	  putchar('-');
	  break;
	default:
	  break;
	}
	printf(type == ty_uuuid ? "%02X" : "%02x", ch);
	nchar--;
	break;
      }
  }
}


int main(int argc, char *argv[])
{
  int opt;
  int nchar = 8;		/* Characters wanted */
  int decor = 0;		/* Precede hex numbers with 0x, oct with 0 */
  int monocase = 0;		/* 1 for lower, 2 for upper */
  enum output_type type = ty_ascii;
  int i;

  program = argv[0];

  while ((opt = getopt_long(argc, argv, short_options,
			    long_options, NULL)) != EOF) {
    switch (opt) {
    case OPT_ASCII:		/* ASCII */
      type = ty_ascii;
      break;
    case 'a':			/* Alphanum only */
      type = ty_anum;
      break;
    case 'l':			/* Lower case alphanum */
      type = ty_lcase;
      break;
    case 'u':			/* Upper case alphanum */
      type = ty_ucase;
      break;
    case 'x':			/* Hexadecimal number */
      type = ty_hex;
      break;
    case 'X':			/* Upper case hex number */
      type = ty_uhex;
      break;
    case 'd':			/* Decimal number */
      type = ty_dec;
      break;
    case 'o':			/* Octal number */
      type = ty_oct;
      break;
    case 'b':		     	/* Binary number (for Bynar saboteurs) */
      type = ty_binary;
      break;
    case 'A':			/* Alphabetic */
      type = ty_alpha;
      break;
    case 'L':			/* Lower case alphabetic */
      type = ty_alcase;
      break;
    case 'U':			/* Upper case alphabetic */
      type = ty_aucase;
      break;
    case 'i':			/* IP address suffix */
      type = ty_ip;
      nchar = 2;
      break;
    case 'm':			/* Lower case MAC address */
      type = ty_mac;
      nchar = 6;
      break;
    case 'M':			/* Upper case MAC address */
      type = ty_umac;
      nchar = 6;
      break;
    case 'g':			/* UUID/GUID */
      type = ty_uuid;
      nchar = 16;
      break;
    case 's':		       /* Use /dev/random, not /dev/urandom */
      secure_source = 1;
      break;
    case 'c':			/* C constant */
      decor = 1;
      break;
    case OPT_LOWER:		/* --lower */
      monocase = 1;
      break;
    case OPT_UPPER:		/* --upper */
      monocase = 2;
      break;
    case 'h':
      usage(0);
      break;
    case 'V':
      printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      exit(0);
    default:
      usage(1);
      break;
    }
  }

  for (i = optind; i < argc; i++) {
    nchar = atoi(argv[i]);
    if ( nchar < 1 )
      usage(1);
  }

  setrandom();

  /* Adjust type for monocasing */
  if (monocase)
    switch (type) {
    case ty_ascii:
    case ty_anum:
    case ty_alpha:
      type += monocase;
      break;
    case ty_hex:
    case ty_mac:
    case ty_uuid:
      type += monocase-1;
      break;
    default:
      break;
    }

  if ( decor ) {
    switch ( type ) {
    case ty_hex:
    case ty_uhex:
      putchar('0'); putchar('x');
      break;
    case ty_oct:
      putchar('0');
      break;
    case ty_dec:
      /* Do nothing - handled later */
      break;
    default:
      putchar('\"');
      break;
    }
  }

  output_random(type, nchar, decor);

  
  if ( decor ) {
    switch ( type ) {
    case ty_hex:
    case ty_uhex:
    case ty_oct:
    case ty_dec:
      /* Do nothing */
      break;
    default:
      putchar('\"');
      break;
    }
  }

  putchar('\n');

  exit(0);
}
