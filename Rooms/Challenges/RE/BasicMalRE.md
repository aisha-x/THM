# TryHackMe: Basic Malware RE

https://medium.com/@d3lt4labs/basic-malware-re-tryhackme-walkthrough-27b07ce6b694

## Strings 1

This executable prints an MD5 Hash on the screen when executed. Can you grab the exact flag?

Note: You don't need to run the executable!

```powershell
76b58619d2834419e82e0f6a605c8811
```

Open Ghidra and import the malware to CodeBrowser. We found part of the flag in the decompiled entry function

<img width="1920" height="981" alt="image" src="https://github.com/user-attachments/assets/3e96ea09-1334-455c-8ffc-d119fbb3efa5" />

Double-click on the memory address 00424828 to send us to the flag

<img width="1105" height="688" alt="image" src="https://github.com/user-attachments/assets/5464b44c-3143-40ed-8bd7-86044bcf9447" />

And here is the complete flag at the memory address 00424828 

<img width="985" height="438" alt="image" src="https://github.com/user-attachments/assets/4daa19d3-d1a9-46ba-932b-0e19def45826" />

## Strings 2

The same thing for string2, I found the flag in the decompiled entry function

<img width="1920" height="981" alt="image" src="https://github.com/user-attachments/assets/6fddd301-1a55-4d67-b6f5-fc3ef842af8f" />

## Strings3

As for the last one, the entry function contained two functions: LoadSteringA and FindResources

<img width="703" height="504" alt="image" src="https://github.com/user-attachments/assets/2d26b761-1c51-46d4-8283-cfe97a93c7d6" />

referred to [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringa), 

```cpp
int LoadStringA(
  [in, optional] HINSTANCE hInstance,
  [in]           UINT      uID,
  [out]          LPSTR     lpBuffer,
  [in]           int       cchBufferMax
);
```

This function `LoadStringA`loads a string from the executable file, and the parameter `uID`is the identifier of the string to be loaded, which in our case is 0x110 → 272 in decimal. Go to the Program Trees tab, in the .rsrc section, which will contain resource information for a module, then search for the string ID 272

<img width="1214" height="596" alt="image" src="https://github.com/user-attachments/assets/3ff53cf5-7582-45d3-81b7-25c297247169" />
