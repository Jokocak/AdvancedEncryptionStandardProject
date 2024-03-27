/**
        @file io.h
        @author James O Kocak (jokocak)
        
        The header file for the io.c component of the program. This file
        contains all the includes and documentation for the provided functions.
 */

#include "field.h"
#include <stdlib.h>
#include <stdio.h>

/**
        This function reads the contents of the binary file with the given
        name. It returns a pointer to a dynamically allocated array of bytes
        containing the entire file contents. The size parameter is an integer
        that is passed by reference to this function. The function fills in
        this integer with the total size of the file, how many bytes are in the
        returned array.

        @param filename The file to read from
        @param size The number of bytes that are in the array after reading is
                        complete
        @return An array of the bytes read from the file
 */
byte *readBinaryFile( char const *filename, int *size );

/**
        This function writes the contents of the given data array, in binary,
        to the file with the given name. The size parameter says how many bytes
        are contained in the data array.

        @param filename The file to write to
        @param data The array of bytes
        @param size The amount of bytes in the array
 */
void writeBinaryFile( char const *filename, byte *data, int size );
