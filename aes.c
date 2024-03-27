/**
        @file aes.c
        @author James O Kocak (jokocak)
        
        This component of the program contains all the functions required to
        properly encrypt and decrypt a given file.
 */

#include "aes.h"

/** The starting index of fourth word */
#define FOURTH_START 15

/** The end index of fourth word and start of third */
#define THIRD_START 11

/** The end index of third word and start of second */
#define SECOND_START 7

/** The end index of second and start of first */
#define SECOND_END 3

/** The end index of first */
#define FIRST_END -1

/** The index for the second row of a square */
#define SECOND_ROW 1

/** The index for the third row of a square */
#define THIRD_ROW 2

/** The index for the fourth row of a square */
#define FOURTH_ROW 3

/**
        Return the sBox substitution value for a given byte value.

        @param v byte input value.
        @return substitution for the given byte.
*/
static byte substBox( byte v )
{
        // Forward-direction replacement map for the sBox.
        static const byte rule[] =
        { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
                0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
                0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
                0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
                0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
                0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
                0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
                0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
                0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
                0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
                0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
                0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
                0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
                0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
                0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
                0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

        // Return the replacement for v based on the map.
        return rule[ v ];
}

/**
        Return the inverse sBox substitution value for a given byte value.

        @param v byte input value.
        @return inverse substitution for the given byte.
*/
static byte invSubstBox( byte v )
{
        // Inverse-direction replacement map for the sBox.
        static const byte irule[] =
        { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
                0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
                0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
                0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
                0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
                0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
                0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
                0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
                0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
                0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
                0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
                0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
                0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
                0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
                0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
                0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

        // Return the (inverse) replacement for v based on the map.
        return irule[ v ];
}

void gFunction( byte dest[ WORD_SIZE ], byte const src[ WORD_SIZE ], int r )
{
        // Constant values used in each round of the g function.
        static const byte roundConstant[ ROUNDS + 1 ] = {
                0x00, // First element not used.
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };

        // Applies g function
        int i = 0;
        for ( i = 0; i < WORD_SIZE; i++ ) {
                // If first byte of input is being rearranged
                if ( i == 0 ) {
                        dest[ WORD_SIZE - 1 ] = substBox( src[ i ] );
                } else if ( i == 1 ) { // If first byte of dest is being made
                        dest[ i - 1 ] = substBox( src[ i ] ) ^
                                                roundConstant[ r ] ;
                } else { // Other bytes
                        dest[ i - 1 ] = substBox( src[ i ] );
                }
        }
}

/**
        This helper function to generate subkeys grabs a word according to the passed in indexes.

        @param subkey The array to get a word from
        @param index The index of the subkey to get a word from
        @param startIndex The index of word to start from
        @param endIndex The index of word to end at
        @param word The array to put data into
 */
static void getWord( byte subkey[ ROUNDS + 1 ][ BLOCK_SIZE ],
                                int index, int startIndex, int endIndex,
                                byte word[ WORD_SIZE ] )
{
        // Reads keys into word
        int size = WORD_SIZE - 1;
        int i = 0;
        for ( i = startIndex; i > endIndex; i-- ) {
                word[ size-- ] = subkey[ index ][ i ];
        }
}

void generateSubkeys( byte subkey[ ROUNDS + 1 ][ BLOCK_SIZE ],
                        byte const key[ BLOCK_SIZE ] )
{
        // Generates subkeys in loop
        int i = 0;
        int j = 0;
        for ( i = 0; i < ROUNDS + 1; i++ ) {
                // First subkey is just a copy of original key
                if ( i == 0 ) {
                        for ( j = 0; j < BLOCK_SIZE; j++ ) {
                                subkey[ i ][ j ] = key[ j ];
                        }
                } else { // If not first subkey
                        // Gets First word
                        byte first[ WORD_SIZE ];
                        getWord( subkey, i - 1, SECOND_END,
                                FIRST_END, first );

                        // Gets Second word
                        byte second[ WORD_SIZE ];
                        getWord( subkey, i - 1, SECOND_START,
                                SECOND_END, second );

                        // Gets Third Word
                        byte third[ WORD_SIZE ];
                        getWord( subkey,i - 1, THIRD_START,
                                SECOND_START, third );

                        // Gets Fourth Word
                        byte fourth[ WORD_SIZE ];
                        getWord( subkey, i - 1, FOURTH_START,
                                THIRD_START, fourth );
                        
                        // Gets gfunction of Fourth Word
                        byte gFourth[ WORD_SIZE ];
                        gFunction( gFourth, fourth, i );

                        // Exclusive or the first 4 (0-3) of previous subkey,
                        // along with the last 4 (12-15) put into a gfunction
                        byte previousResult[ WORD_SIZE ];
                        int size = 0;
                        for ( j = 0; j < BLOCK_SIZE; j++ ) {
                                // Resets size if need to
                                if ( size == WORD_SIZE ) {
                                        size = 0;
                                }

                                if ( j <= SECOND_END ) {
                                        // Exclusive ors first word and the
                                        // gfunction of the fourth word
                                        subkey[ i ][ j ] = first[ size ] ^
                                                        gFourth[ size ];

                                        // Copies previous result
                                        previousResult[ size++ ] =
                                                        subkey[ i ][ j ];
                                } else if ( j <= SECOND_START ) {
                                        // Exclusive ors second word with
                                        // previous result
                                        subkey[ i ][ j ] = second[ size ] ^
                                                previousResult[ size ];

                                        // Copies previous result
                                        previousResult[ size++ ] =
                                                        subkey[ i ][ j ];
                                } else if ( j <= THIRD_START ) {
                                        // Exclusive ors third word with
                                        // previous result
                                        subkey[ i ][ j ] = third[ size ] ^
                                                previousResult[ size ];

                                        // Copies previous result
                                        previousResult[ size++ ] =
                                                        subkey[ i ][ j ];
                                } else if ( j <= FOURTH_START ) {
                                        // Exclusive ors third word with
                                        // previous result
                                        subkey[ i ][ j ] = fourth[ size ] ^
                                                previousResult[ size ];

                                        // Copies previous result
                                        previousResult[ size++ ] =
                                                        subkey[ i ][ j ];
                                }
                        }
                }
        }
}

void addSubkey( byte data[ BLOCK_SIZE ], byte const key[ BLOCK_SIZE ] )
{
        // Adds each subkey
        int i = 0;
        for ( i = 0; i < BLOCK_SIZE; i++ ) {
                data[ i ] = fieldAdd( data[ i ], key[ i ] );
        }
}

void blockToSquare( byte square[ BLOCK_ROWS ][ BLOCK_COLS ],
                        byte const data[ BLOCK_SIZE ] )
{
        // Arranges block of data into a square
        int i = 0;
        int j = 0;
        int offset = 0;
        for ( i = 0; i < BLOCK_COLS; i++ ) {
                // Adds 4 to offset if not first column
                if ( i != 0 ) {
                        offset += WORD_SIZE;
                }

                // Fills in square
                for ( j = 0; j < BLOCK_ROWS; j++ ) {
                        square[ j ][ i ] = data[ j + offset ];
                }
        }
}

void squareToBlock( byte data[ BLOCK_SIZE ],
                        byte const square[ BLOCK_ROWS ][ BLOCK_COLS ] )
{
        // Arranges square of data back into a block of data
        int i = 0;
        int j = 0;
        int offset = 0;
        for ( i = 0; i < BLOCK_COLS; i++ ) {
                // Adds 4 to offset if not first column
                if ( i != 0 ) {
                        offset += WORD_SIZE;
                }

                for ( j = 0; j < BLOCK_ROWS; j++ ) {
                        data[ j + offset ] = square[ j ][ i ];
                }
        }
}

/**
        This function is a helper to shiftRows, it shifts the rows in the
        array accordingly and uses the offset to tell how many columns over to
        shift.

        @param square The square to shift
        @param offset The number of columns to offset the shift by
 */
static void shiftRowHelper( byte square[ BLOCK_ROWS ][ BLOCK_COLS ],
                                int offset )
{
        // Bytes to hold place holders
        int j = 0;
        byte placeHolder = 0;
        byte placeHolder2 = 0;

        // Switch statement for offset
        switch ( offset ) {
                case SECOND_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        // Records first element in row
                                        placeHolder = square[ offset ][ j ];

                                        // Shifts row
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                } else if ( j == BLOCK_COLS - 1 ) {
                                        // Shifts with placeHolder
                                        square[ offset ][ j ] = placeHolder;
                                } else {
                                        // Shifts with adjacent slot
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                }
                        }
                        break;
                case THIRD_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        // Records first element in row
                                        placeHolder = square[ offset ][ j ];

                                        // Shifts row
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                } else if ( j == 1 ) {
                                        // Records second element in row
                                        placeHolder2 = square[ offset ][ j ];

                                        // Shifts row
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                } else if ( j == THIRD_ROW ) {
                                        square[ offset ][ j ] = placeHolder;
                                } else if ( j == FOURTH_ROW ) {
                                        square[ offset ][ j ] = placeHolder2;
                                }
                        } 
                        break;
                case FOURTH_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        placeHolder = square[ offset ][ j ];

                                        square[ offset ][ j ] =
                                                square[ offset ][ BLOCK_COLS - 1 ];
                                } else if ( j == 1 ) {
                                        placeHolder2 = square[ offset ][ j ];

                                        square[ offset][ j ] = placeHolder;
                                } else if ( j == THIRD_ROW ) {
                                        placeHolder = square[ offset ][ j ];

                                        square[ offset ][ j ] = placeHolder2;
                                } else if ( j == FOURTH_ROW ) {
                                        square[ offset ][ j ] = placeHolder;
                                }
                        }
                        break;
        }
}

void shiftRows( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] )
{
        // Shifts rows
        int i = 0;
        for ( i = 1; i < BLOCK_ROWS; i++ ) {
                switch ( i ) {
                        case SECOND_ROW:
                                // Shifts rows by 1
                                shiftRowHelper( square, i );
                                break;

                        case THIRD_ROW:
                                // Shifts rows by 2
                                shiftRowHelper( square, i );
                                break;
                        
                        case FOURTH_ROW:
                                // Shifts rows by 3
                                shiftRowHelper( square, i );
                                break;
                }
        }
}

/**
        This function is a helper to unShiftRows, it unshifts the rows in the
        array accordingly and uses the offset to tell how many columns over to
        unshift.

        @param square The square to shift
        @param offset The number of columns to offset the shift by
 */
static void unShiftRowHelper( byte square[ BLOCK_ROWS ][ BLOCK_COLS ],
                                int offset )
{
        // Bytes to hold place holders
        int j = 0;
        byte placeHolder = 0;
        byte placeHolder2 = 0;

        // Switch statement for offset
        switch ( offset ) {
                case SECOND_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        placeHolder = square[ offset ][ j ];

                                        square[ offset ][ j ] =
                                                square[ offset ][ BLOCK_COLS - 1 ];
                                } else if ( j == 1 ) {
                                        placeHolder2 = square[ offset ][ j ];

                                        square[ offset ][ j ] = placeHolder;
                                } else if ( j == THIRD_ROW ) {
                                        placeHolder = square[ offset ][ j ];

                                        square[ offset ][ j ] = placeHolder2;
                                } else if ( j == FOURTH_ROW ) {
                                        square[ offset ][ j ] = placeHolder;
                                }
                        }
                        break;
                case THIRD_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        // Records first element in row
                                        placeHolder = square[ offset ][ j ];

                                        // Shifts row
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                } else if ( j == 1 ) {
                                        // Records second element in row
                                        placeHolder2 = square[ offset ][ j ];

                                        // Shifts row
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + offset ];
                                } else if ( j == THIRD_ROW ) {
                                        square[ offset ][ j ] = placeHolder;
                                } else if ( j == FOURTH_ROW ) {
                                        square[ offset ][ j ] = placeHolder2;
                                }
                        } 
                        break;
                case FOURTH_ROW:
                        for ( j = 0; j < BLOCK_COLS; j++ ) {
                                if ( j == 0 ) {
                                        placeHolder = square[ offset ][ j ];

                                        square[ offset ][ j ] = square[ offset ][ j + 1 ];
                                } else if ( j == BLOCK_COLS - 1 ) {
                                        square[ offset ][ j ] = placeHolder;
                                } else {
                                        square[ offset ][ j ] =
                                                square[ offset ][ j + 1 ];
                                }
                        }
                        break;
        }
}

void unShiftRows( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] )
{
        // Unshifts rows
        int i = 0;
        for ( i = 1; i < BLOCK_ROWS; i++ ) {
                switch ( i ) {
                        case SECOND_ROW:
                                // Shifts rows by 1
                                unShiftRowHelper( square, i );
                                break;

                        case THIRD_ROW:
                                // Shifts rows by 2
                                unShiftRowHelper( square, i );
                                break;
                        
                        case FOURTH_ROW:
                                // Shifts rows by 3
                                unShiftRowHelper( square, i );
                                break;
                }
        }
}

void mixColumns( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] )
{
        // Matrix by which each column of square is multiplied.
        static const byte mixMatrix[ BLOCK_ROWS ][ BLOCK_COLS ] = {
                { 0x02, 0x03, 0x01, 0x01 },
                { 0x01, 0x02, 0x03, 0x01 },
                { 0x01, 0x01, 0x02, 0x03 },
                { 0x03, 0x01, 0x01, 0x02 }
        };

        // Makes array to hold output
        byte mult[ BLOCK_ROWS ][ BLOCK_COLS ];

        // Performs matrix multiplication on the square
        int i = 0;
        int j = 0;
        int k = 0;
        int product = 0;
        int sum = 0;
        for ( i = 0; i < BLOCK_ROWS; i++ ) {
                for ( j = 0; j < BLOCK_COLS; j++ ) {
                        for ( k = 0; k < BLOCK_ROWS; k++ ) {
                                product = fieldMul( square[ k ][ j ],
                                                mixMatrix[ i ][ k ] );

                                if ( k == 0 ) {
                                        sum = product;
                                } else {
                                        sum = fieldAdd( sum, product );
                                }
                        }

                        mult[ i ][ j ] = sum;
                        sum = 0;
                }
        }

        // Copies calculated matrix to square
        for ( i = 0; i < BLOCK_ROWS; i++ ) {
                for ( j = 0; j < BLOCK_COLS; j++ ) {
                        square[ i ][ j ] = mult[ i ][ j ];
                }
        }
}

void unMixColumns( byte square[ BLOCK_ROWS ][ BLOCK_COLS ] )
{
        // Matrix by which each column of square is multiplied.
        static const byte invMixMatrix[ BLOCK_ROWS ][ BLOCK_COLS ] = {
                { 0x0E, 0x0B, 0x0D, 0x09 },
                { 0x09, 0x0E, 0x0B, 0x0D },
                { 0x0D, 0x09, 0x0E, 0x0B },
                { 0x0B, 0x0D, 0x09, 0x0E }
        };

        // Makes array to hold output
        byte mult[ BLOCK_ROWS ][ BLOCK_COLS ];

        // Performs matrix multiplication on the square
        int i = 0;
        int j = 0;
        int k = 0;
        int product = 0;
        int sum = 0;
        for ( i = 0; i < BLOCK_ROWS; i++ ) {
                for ( j = 0; j < BLOCK_COLS; j++ ) {
                        for ( k = 0; k < BLOCK_ROWS; k++ ) {
                                product = fieldMul( square[ k ][ j ],
                                                invMixMatrix[ i ][ k ] );

                                if ( k == 0 ) {
                                        sum = product;
                                } else {
                                        sum = fieldAdd( sum, product );
                                }
                        }

                        mult[ i ][ j ] = sum;
                        sum = 0;
                }
        }

        // Copies calculated matrix to square
        for ( i = 0; i < BLOCK_ROWS; i++ ) {
                for ( j = 0; j < BLOCK_COLS; j++ ) {
                        square[ i ][ j ] = mult[ i ][ j ];
                }
        }
}

void encryptBlock( byte data[ BLOCK_SIZE ], byte key[ BLOCK_SIZE ] )
{
        // Defines square for use
        byte square[ BLOCK_ROWS ][ BLOCK_COLS ];

        // Generates Subkeys
        byte subkey[ ROUNDS + 1 ][ BLOCK_SIZE ];
        generateSubkeys( subkey, key );

        // Adds First Subkey
        addSubkey( data, subkey[ 0 ] );

        // Starts rounds of encryption
        int i = 0;
        int j = 0;
        for ( i = 1; i < ROUNDS + 1; i++ ) {
                // Runs every byte through substBox function
                for ( j = 0; j < BLOCK_SIZE; j++ ) {
                        data[ j ] = substBox( data[ j ] );
                }

                // Block to Square Operation
                blockToSquare( square, data );

                // Shift Rows Operation
                shiftRows( square );

                // Mix Columns Operation, Skips on Round 10
                if ( i != ROUNDS ) {
                        mixColumns( square );
                }

                // Square to Block Operation
                squareToBlock( data, square );

                // Add Subkey
                addSubkey( data, subkey[ i ] );
        }
}

void decryptBlock( byte data[ BLOCK_SIZE ], byte key[ BLOCK_SIZE ] )
{
        // Defines square for use
        byte square[ BLOCK_ROWS ][ BLOCK_COLS ];

        // Generates Subkeys
        byte subkey[ ROUNDS + 1 ][ BLOCK_SIZE ];
        generateSubkeys( subkey, key );

        // Starts decryption
        int i = 0;
        int j = 0;
        for ( i = ROUNDS; i > 0; i-- ) {
                // Add Subkey
                addSubkey( data, subkey[ i ] );

                // Block to Square Operation
                blockToSquare( square, data );

                // Mix Columns Operation
                if ( i != ROUNDS ) {
                        unMixColumns( square );
                }

                // Shift Rows Operation
                unShiftRows( square );

                // Square to Block Operation
                squareToBlock( data, square );

                // Runs every byte through substBox function
                for ( j = 0; j < BLOCK_SIZE; j++ ) {
                        data[ j ] = invSubstBox( data[ j ] );
                }
        }

        // After all Rounds completed
        addSubkey( data, key );
}
