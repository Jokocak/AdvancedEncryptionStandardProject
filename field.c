/**
        @file field.c
        @author James O Kocak (jokocak)
        
        This function contains functions for addition, subtraction, and
        multiplication in the 8-bit Galois field used by AES.
 */

#include "field.h"

/** The number used to reduce bits to 8 bits */
#define REDUCER 0x11B

byte fieldAdd( byte a, byte b )
{
        return a ^ b;
}

byte fieldSub( byte a, byte b )
{
        return a ^ b;
}

/**
        This helper function to fieldMul gets the most significant one of the
        set of bits to ensure that the most significant one is within the
        first 8 bits.

        @param product The current product to check for where the 1 bit is
        @return The index of the most significant one in the bit sequence
                        of product
 */
static int getMostSignificantOne( const long product )
{
        int i = 0;
        int index = 0;
        for ( i = 0; i < BBITS * sizeof( int ); i++ ) {
                if ( product & ( 1 << i ) ) {
                        index = i;
                }
        }

        return index;
}

byte fieldMul( byte a, byte b )
{
        // Creates byte to return product
        long product = 0;

        // Creates long for a so that 16 bits can be held for shifting
        long newA = a;

        // Starts on least significant bit of b, Repeatedly shifts left
        // and adding a to product if current bit at b is a 1
        int i = 0;
        for ( i = 0; i < BBITS; i++ ) {
                // If the first bit of b is 1, add 
                if ( b & 0x01 ) {
                        product ^= newA;
                }

                // Shifts a one bit to the left
                newA <<= 0x01;

                // Shifts b one bit to the right
                b >>= 0x01;
        }

        // Creates index to hold most significant one place
        int index = getMostSignificantOne( product );

        // Moves reducer to most significant ones place
        long reducer = REDUCER;
        for ( i = 0; i < ( index - BBITS ); i++ ) {
                reducer <<= 0x01;
        }

        // Repeatedly ors most significant ones place until product fits in 8
        // bits
        int previousIndex = 0;
        while ( index >= BBITS ) {
                // Exclusively ors product
                product ^= reducer;

                // Shifts reducer accordingly
                previousIndex = index;
                index = getMostSignificantOne( product );
                reducer >>= ( previousIndex - index );
        }

        // Returns product
        byte rtn = product;
        return rtn;
}
