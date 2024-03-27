/**
        @file field.h
        @author James O Kocak (jokocak)
        
        The header file for the field.c component of the program. This file
        contains all the includes and documentation for the provided functions.
 */

#ifndef _FIELD_H_
#define _FIELD_H_

#include <stdlib.h>
#include <math.h>

/** Type used for our field, an unsigned byte. */
typedef unsigned char byte;

/** Number of bits in a byte. */
#define BBITS 8

#endif

/**
        This function performs the addition operation in the 8-bit Galois field
        used by AES. Both a and b are added together and returned.

        @param a The first byte to add
        @param b The second byte to add
        @return The result of the addition of a and b
 */
byte fieldAdd( byte a, byte b );

/**
        This function performs the subtraction operation in the 8-bit Galois
        field used by AES. In this case, b is subtracted from a and that result
        is returned.

        @param a The byte to be subtracted
        @param b The byte to subtract from a
        @return The result of the subtraction of b from a
 */
byte fieldSub( byte a, byte b );

/**
        This function performs the multiplication operation in the 8-bit Galois
        field used by AES. Both a and b are multiplied and the result is
        returned.

        @param a The first byte to multiply
        @param b The second byte to multiply
        @return The result of the multiplication of a and b
 */
byte fieldMul( byte a, byte b );
