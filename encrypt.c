/**
        @file encrypt.c
        @author James O Kocak (jokocak)
        
        This file contains the main method for the encrypt program, this
        program uses all of the other components to perform AES encryption
        and to write out the ciphertext output.
 */

// #include "io.c"
// #include "aes.h"
// #include "aes.c"
#include "field.c"
#include "io.c"
#include "aes.c"

/** The minimum number of arguments */
#define ARG_COUNT 4

/** The index with which the input file resides in argv */
#define INPUT_INDEX 2

/** The index with which the key file resides in argv */
#define KEY_INDEX 1

/** The index with which the output file resides in argv */
#define OUTPUT_INDEX 3

/**
        This function serves as a helper function when encrypting more than
        one block of data.  It reads the index of the current block in
        inputBytes into the block array from the startIndex to the endIndex.

        @param inputBytes The entire array of bytes from input
        @param block The array to read the current block into
        @param startIndex The start index of the current block
        @param endIndex The end index of the current block
 */
static void setBlock( byte *inputBytes, byte block[ BLOCK_SIZE ],
                        int startIndex, int endIndex )
{
        int i;
        int blockSize = 0;
        for ( i = startIndex; i <= endIndex; i++ ) {
                block[ blockSize++ ] = inputBytes[ i ];
        }
}

/**
        This function serves as a helper function when encrypting multiple
        blocks of data. This function takes the block array and inserts its
        contents back into the original inputBytes array after encryption.

        @param inputBytes The entire array of bytes from input
        @param block The array of encrypted data
        @param startIndex The start index of the current block
        @param endIndex The end index of the current block
 */
static void setBlockData( byte *inputBytes, byte block[ BLOCK_SIZE ],
                                int startIndex, int endIndex )
{
        int i;
        int blockSize = 0;
        for ( i = startIndex; i <= endIndex; i++ ) {
                inputBytes[ i ] = block[ blockSize++ ];
        }
}

/**
        This main function uses the other components to read an input file,
        perform AES encryption, and writes out the ciphertext output.

        @param argc The number of arguments
        @param argv An array of the arguments
        @return Program Exit Status
 */
int main( int argc, char *argv[] )
{
        // Checks if correct amount of args
        if ( argc != ARG_COUNT ) {
                fprintf( stderr,
                        "usage: encrypt <key-file> <input-file> <output-file>\n" );
                exit( EXIT_FAILURE );
        }

        // Reads input file and key file
        int inputSize;
        byte *inputBytes = readBinaryFile( argv[ INPUT_INDEX ], &inputSize );
        int keySize;
        byte *keyBytes = readBinaryFile( argv[ KEY_INDEX ], &keySize );

        // Checks if key is 16 bytes in length
        if ( keySize != BLOCK_SIZE ) {
                fprintf( stderr, "Bad key file: %s\n", argv[ KEY_INDEX ] );
                exit( EXIT_FAILURE );
        }

        // Checks if inputSize is a multiple of 16
        if ( inputSize % BLOCK_SIZE != 0 ) {
                fprintf( stderr, "Bad plaintext file length: %s\n",
                        argv[ INPUT_INDEX ] );
                exit( EXIT_FAILURE );
        }

        // Perform AES encryption
        if ( inputSize == BLOCK_SIZE ) {
                encryptBlock( inputBytes, keyBytes );
        } else {
                // Creates variable to get number of Blocks
                int numBlocks = inputSize / BLOCK_SIZE;

                // Sets beginning block indexes
                int startIndex = 0;
                int endIndex = BLOCK_SIZE - 1;

                // Creates block for use in encryption
                byte block[ BLOCK_SIZE ];

                // Encrypts each block of data
                int i;
                for ( i = 0; i < numBlocks; i++ ) {
                        // Gets current block to encrypt
                        setBlock( inputBytes, block, startIndex, endIndex );

                        // Encrypts the block
                        encryptBlock( block, keyBytes );

                        // Sets the encrypted block in inputBytes array
                        setBlockData( inputBytes, block, startIndex, endIndex );

                        // Moves to next block
                        startIndex += BLOCK_SIZE;
                        endIndex += BLOCK_SIZE;
                }
        }

        // Write out ciphertext output
        writeBinaryFile( argv[ OUTPUT_INDEX ], inputBytes, inputSize );

        // Frees memory
        free( inputBytes );
        free( keyBytes );

        // Returns successful exit status
        return EXIT_SUCCESS;
}
