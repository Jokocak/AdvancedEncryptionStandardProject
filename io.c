/**
        @file io.c
        @author James O Kocak (jokocak)
        
        This component handles the reading and writing of information from
        binary files.
 */

#include "io.h"

byte *readBinaryFile( char const *filename, int *size )
{
        // Creates file pointer to Binary file for reading
        FILE *read = fopen( filename, "rb" );

        // Checks if file exists
        if ( read == NULL ) {
                fprintf( stderr, "Can't open file: %s\n", filename );
                exit( EXIT_FAILURE );
        }

        // Count number of bytes in file so no reallocation is required
        int capacity = 0;
        while ( fgetc( read ) != EOF ) {
                capacity++;
        }

        // Rewinds to start of file for fread
        rewind( read );

        // Dynamically allocates array of bytes
        byte *bytes = ( byte * ) malloc( capacity * sizeof( byte ) );

        // Records number of bytes in file into the size field
        fread( bytes, sizeof( byte ), capacity, read );

        // Records size of file
        *size = capacity;

        // Closes reader
        fclose( read );

        // Returns dynamically allocated array of bytes
        return bytes;
}

void writeBinaryFile( char const *filename, byte *data, int size )
{
        // Creates file pointer for writing in Binary
        FILE *ptr = fopen( filename, "wb" );

        // Writes bytes to file
        fwrite( data, sizeof( byte ), size, ptr );

        // Closes writer
        fclose( ptr );
}
