/**
        @file aes.h
        @author James O Kocak (jokocak)
        
        The header file for the aes.c component of the program. This file
        contains all the includes and documentation for the provided functions.
 */

#ifndef _AES_H_
#define _AES_H_

#include "field.h"
//#include <math.h>
#include <stdbool.h>
//#include <stdlib.h>
#include <stdio.h>

/** Number of bytes in an AES key or an AES block. */
#define BLOCK_SIZE 16

/** Numer of rows when a data block is arranged in a square. */
#define BLOCK_ROWS 4

/** Numer of columns when a data block is arranged in a square. */
#define BLOCK_COLS 4

/** Number of bytes in a word. */
#define WORD_SIZE 4

/** Number of roudns for 128-bit AES. */
#define ROUNDS 10

#endif

/**
        This function computes the g function used in generating the subkeys
        from the original, 16-byte key. It takes a 4-byte input via the src
        parameter and returns a 4-byte result via the dest parameter. The value,
        r, gives the round number, between 1 and 10 inclusively.

        @param dest The result of the g function
        @param src The input to the g function
        @param r The round number, between 1 and 10 inclusively
 */
void gFunction( byte dest[ WORD_SIZE ], byte const src[ WORD_SIZE ], int r );

/**
        This function fills in the subkey array with subkeys for each round of
        AES, computed from the given key.

        @param subkey The array of subkeys to fill
        @param key The key to compute the subkeys with
 */
void generateSubkeys( byte subkey[ ROUNDS + 1 ][ BLOCK_SIZE ], byte const key[ BLOCK_SIZE ] );

/**
        This function performs the addSubkey operation, adding the given subkey
        to the given data array.

        @param data The array of data
        @param key The key to add to the array of data
 */
void addSubkey( byte data[ BLOCK_SIZE ], byte const key[ BLOCK_SIZE ] );

/**
        This function rearranges a block of 16 data values from the
        one-dimensional arrangement to the 4x4 arrangement.

        @param square The 2D array represents a square
        @param data The block of data to rearrange
 */
void blockToSquare( byte square[ BLOCK_ROWS ][ BLOCK_COLS ],
                        byte const data[ BLOCK_SIZE ] );

/**
        This function requires a 4x4 arrangement of data values, returning them
        as a one-dimensional array of 16 values.

        @param data The block of data to represent one-dimensional array
        @param square The 2D array that represents a square
 */
void squareToBlock( byte data[ BLOCK_SIZE ],
                        byte const square[ BLOCK_ROWS ][ BLOCK_COLS ] );

/**
        This function performs the shiftRows operation on the given 4x4 square
        of values.

        @param square The square to perform the operation on
 */
void shiftRows( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] );

/**
        This function performs the inverse shiftRows operation on the given
        4x4 square of values.

        @param square The square to perform the operation on
 */
void unShiftRows( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] );

/**
        This function performs the mixColumns operation on the given 4x4 square
        of values, multiplying each column by the mixMatrix.

        @param square The square to perform the operation on
 */
void mixColumns( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] );

/**
        This function performs the inverse of the mixColumns operation on the
        given 4x4 square of values, multiplying each column by the
        invMixMatrix.

        @param square The square to perform the operation on
 */
void unMixColumns( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] );

/**
        This function encrypts a 16-byte block of data using the given key.
        It generates 11 subkeys from key, adds the first subkey, then performs
        the 10 rounds of operations needed to encrypt the block.

        @param data The block of data to encrypt
        @param key The key to generate subkeys from
 */
void encryptBlock( byte data[ BLOCK_SIZE ], byte key[ BLOCK_SIZE ] );

/**
        This function decrypts a 16-byte block of data using the given key.
        It generates the 11 subkeys from key, then performs the 10 rounds of
        inverse operations, and then an addSubkey to decrypt the block.

        @param data The block of data to decrypt
        @param key The key to generate subkeys from
 */
void decryptBlock( byte data[ BLOCK_SIZE ], byte key[ BLOCK_SIZE ] );
