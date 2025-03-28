# Metasploit: Meterpreter | TryHackMe Walkthrough

Room URL: 

# Task 3 | Meterpreter Commands

Typing help on any Meterpreter session (shown by meterpreter> at the prompt) will list all available commands.

The Meterpreter help menu

```
meterpreter > help
Core Commands
=============
    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel[...]
```

Every version of Meterpreter will have different command options, so running the help command is always a good idea. Commands are built-in tools available on Meterpreter. They will run on the target system without loading any additional script or executable files.

Meterpreter will provide you with three primary categories of tools;

 - Built-in commands
 - Meterpreter tools
 - Meterpreter scripting

If you run the help command, you will see Meterpreter commands are listed under different categories.

 - Core commands
 - File system commands
 - Networking commands
 - System commands
 - User interface commands
 - Webcam commands
 - Audio output commands
 - Elevate commands
 - Password database commands
 - Timestomp commands
