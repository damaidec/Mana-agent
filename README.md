# Mana Agent

Mana agent is a custom agent for havoc built around Talon agent as basis. When I got free time, I will be adding more capabilities on this agent. 

# Setup

Follow the installation guide on havoc-py
https://github.com/HavocFramework/havoc-py

# Features
- Dynamically creates a Config.h for Mana.exe upon payload generation. This reads a hardcoded value path for havoc C2 profile.

## Commands

- shell - Executes cmd commands
- upload - Upload files
- download - Download files
- exit - Terminate process

# Todo

- Test AES http/s communication
- Add more commands prefferably for situational awareness
- String hashing
- Process injections
- some evasion stuffs

# Why I built one ?

Well, I want to improve my understanding on C2 frameworks. I also need to create custom c2 agent for some of my upcoming exams (Most of them will need to evade EDR and I think creating a custom agent could help me pass it since it's not signatured). Lastly probably to have a guide / documentation for building a custom agent for havoc c2 since there is not much blog/information I can find out there aside from https://codex-7.gitbook.io/codexs-terminal-window/red-team/red-team-dev/extending-havoc-c2/third-party-agents