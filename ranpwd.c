/* $Id$ */
/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 1994-2003 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

/*
 * ranpwd.c: Generate random passwords using the Linux kernel-based true
 *           random number generator (if available.)
 */

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

static int ran_fd = 0;		/* /dev/(u)random file descriptor if avail. */
static int secure_source = 0;	/* 1 if we should use /dev/random */

char *program;

/*
 * setrandom(): Attempt to open /dev/(u)random if available, otherwise call
 *              srand()
 */
void setrandom(void)
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

int getrandom(unsigned char *cbuf, size_t nbytes)
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

void cputc(int ch, int esc) {
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

main(int argc, char *argv[])
{
  int i;
  char *oc;
  unsigned char ch;
  int nchar = 8;		/* Characters wanted */
  int decor = 0;		/* Precede hex numbers with 0x, oct with 0 */
  char goodchar[256];		/* Permitted characters */
  enum { ty_ascii, ty_anum, ty_lcase, ty_ucase, ty_alpha, ty_alcase,
	 ty_aucase, ty_hex, ty_uhex, ty_dec, ty_oct, ty_binary }
  type = ty_ascii;

  program = argv[0];

  for ( i = 1 ; i < argc ; i++ )
    {
      if ( argv[i][0] == '-' )
	{
	  for ( oc = argv[i]+1 ; *oc ; oc++ )
	    switch(*oc)
	      {
	      case 'a':		/* Alphanum only */
		type = ty_anum;
		break;
	      case 'l':		/* Lower case alphanum */
		type = ty_lcase;
		break;
	      case 'u':		/* Upper case alphanum */
		type = ty_ucase;
		break;
	      case 'x':		/* Hexadecimal number */
		type = ty_hex;
		break;
	      case 'X':		/* Upper case hex number */
		type = ty_uhex;
		break;
	      case 'd':		/* Decimal number */
		type = ty_dec;
		break;
	      case 'o':		/* Octal number */
		type = ty_oct;
		break;
	      case 'b':		/* Binary number (for Bynar saboteurs) */
		type = ty_binary;
		break;
	      case 'A':		/* Alphabetic */
		type = ty_alpha;
		break;
	      case 'L':		/* Lower case alphabetic */
		type = ty_alcase;
		break;
	      case 'U':		/* Upper case alphabetic */
		type = ty_aucase;
		break;
	      case 's':		/* Use /dev/random, not /dev/urandom */
		secure_source = 1;
		break;
	      case 'c':		/* C constant */
		decor = 1;
		break;
	      default:
		fprintf(stderr, "%s: Unknown switch: -%c\n", argv[0], *oc);
		exit(1);
	      }
	}
      else
	{
	  nchar = atoi(argv[i]);
	  if ( nchar < 1 )
	    {
	      fprintf(stderr, "%s: Invalid argument: %s\n", argv[0], argv[i]);
	      exit(1);
	    }
	}
    }

  setrandom();

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

  while ( nchar )
    {
      switch (type)
	{
	case ty_ascii:
	  getrandom(&ch, 1);
	  ch &= 0x7f;
	  if ( ch >= 0x21 && ch <= 0x7e ) { cputc(ch,decor); nchar--; }
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
	  {
	    int i;
	    getrandom(&ch, 1);
	    i = (nchar < 8) ? nchar : 8;
	    nchar -= i;
	    while ( i-- ) {
	      putchar((ch & 1) + '0');
	      ch >>= 1;
	    }
	    break;
	  }
	}
    }
  
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
