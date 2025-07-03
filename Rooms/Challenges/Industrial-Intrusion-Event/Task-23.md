
# Task-23

the goal is to access Modbus service (on port 502) and investigate a specific registry that contains ASCII-encoded informatio.



scan all registers in blocks of 50 (or 100) and print only ASCII-looking results.

```py
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient(host="<target-ip>", port=502)

def is_ascii(s):
    return all(32 <= c <= 126 or c == 0 for c in s)

if client.connect():
    for start in range(0, 500, 50):  # Scan registers 0-499 in blocks of 50
        result = client.read_holding_registers(address=start, count=50)
        if result.isError():
            print(f"Error reading registers at {start}")
            continue
        
        raw = result.registers
        decoded = ''
        for reg in raw:
            high = (reg >> 8) & 0xFF
            low = reg & 0xFF
            decoded += chr(high) + chr(low)

        ascii_bytes = decoded.encode('latin1')
        printable = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in decoded)

        if any(c.isalnum() for c in printable):  # Print only if there's something readable
            print(f"[{start:03d}] {printable}")
    
    client.close()
else:
    print("Failed to connect to Modbus device.")

```

**output**
```bash
python3 reg2.py
[000] .Y..a...T....W..H......^.F.....N.,h%fK...s-&.?....`.@,|...X....jR....y.?g..w.`.$.!.....+....:.%..`..
[050] f]~..._.LVq..w....j..........Rcxy..0..Y..\..Ht >.......o....h.*.r3...4K,.....QD-.....^>}%@"..w.E....
[100] .;.,B..j.k0.Ds>...jP0.C.KA...O...`.4|. Oz.....}.C.....u..v.D.q.._j....?.....7....... e*.....&......7
[150] '.4..t?...K.G...../.IV*|d..7....A\...`THM{m4nu4l_p0ll1ng_r3g1st3rs}.. -..[F}@2O.0.......s.....b.R.*.
[200] N.l........K..%.}......j.....D..#.;.........f......i....-..A.o...h.n#:EM\D.^..5..s..5.A/U.@.Z...I..L
[250] ..-.v........>B"Q@@.T.1$$...o.......N...w...7..m.xv#SP.M.4..x......p.?.2.R<....i54..(..9....C....%`.
Error reading registers at 300
Error reading registers at 350
Error reading registers at 400
Error reading registers at 450
```
