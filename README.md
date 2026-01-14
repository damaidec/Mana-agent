# Mana Agent

Mana agent is a custom agent for havoc built around Talon agent as basis. When I got free time, I will be adding more capabilities on this agent. 

My blog for making custom havoc agent
https://www.zakodachi.dev/Command-and-control/custom-havoc-agent.html

https://www.zakodachi.dev/Command-and-control/Extending-mana-agent.html

# Setup

Follow the installation guide on havoc-py
https://github.com/HavocFramework/havoc-py

Download donut on https://github.com/TheWover/donut

Open the havoc-py/agent.py, edit the PROFILE_PATH add your full c2 profile, edit DONUT_PATH and add the full path to donut executable

Ensure that on your havoc c2 profile you have a service block configure. Note it should match the endpoint and password for agent.py. After editing it run python agent.py it should register on havoc c2.

Sample havoc c2 profile with Service block

```
Service {
    Endpoint = "test"
    Password = "password1234"
}

```




# Features
- Dynamically creates a Config.h for Mana.exe upon payload generation. This reads a hardcoded value path for havoc C2 profile.

## Supported Listener

- HTTP
- HTTPs

## Supported Output format

## Commands

- shell - Executes cmd commands.                        (Usage: shell /whoami)
- upload - Upload files.                                (Usage:  upload /home/kali/test.txt flag.txt)
- download - Download files.                            (Usage: download flag.txt. This get stored in the loot file of havoc)
- exit - Terminate process.                             (Usage: exit)
- whoami - Get current username and its privilege.      (Usage: whoami)
- ls - list directory files.                            (Usage: ls or ls ../ or ls ../Desktop)
- cd - change directory.                                (Usage: cd ../ or cd <fullpath>)
- pwd - print current working directory.                (Usage: pwd)
- ebapc - Use early bird process injection              (Usage: ebapc <process_path> <shellcode_file>) Note. You must convert Mana.exe first to shell code.

# Todo

- Test AES http/s communication
- Add more commands prefferably for situational awareness
- String hashing
- some evasion stuffs
- Add different output format


# Other Agents for Havoc

- https://github.com/HavocFramework/Talon
- https://github.com/CodeXTF2/PyHmmm
- https://github.com/susMdT/SharpAgent/
- https://github.com/0xTriboulet/Revenant/

# Why I built one ?

Well, I want to improve my understanding on C2 frameworks. I also need to create custom c2 agent for some of my upcoming exams (Most of them will need to evade EDR and I think creating a custom agent could help me around it since it's not signatured). Lastly probably to have a guide / documentation for building a custom agent for havoc c2 since there is not much blog/information I can find out there aside from https://codex-7.gitbook.io/codexs-terminal-window/red-team/red-team-dev/extending-havoc-c2/third-party-agents