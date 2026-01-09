#ifndef MANA_CORE_H
#define MANA_CORE_H

#define PRINT_HEX( b, l )                               \
    printf( #b ": [%d] [ ", l );                        \
    for ( int i = 0 ; i < l; i++ )                      \
    {                                                   \
        printf( "%02x ", ( ( PUCHAR ) b ) [ i ] );      \
    }                                                   \
    puts( "]" );

VOID  ManaInit();

VOID  AnonPipeRead( HANDLE hSTD_OUT_Read );
ULONG RandomNumber32( VOID );

#endif