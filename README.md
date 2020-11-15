# areum
![repo-size badge](https://img.shields.io/github/repo-size/jdeokkim/areum)
![license badge](https://img.shields.io/github/license/jdeokkim/areum)

A basic [Intel 8080](https://en.wikipedia.org/wiki/Intel_8080) CPU emulator written in C.

```console
# ./bin/areum
areum: running res/cpudiag.bin
areum (0x0100): c3 ab 01 ... (JMP addr) | [BC: 0x0000, DE: 0x0000, HL: 0x0000, A: 0x00, SP: 0x0000, C: 0, P: 0, AC: 0, Z: 0, S: 0]
areum (0x01ab): 31 ad 07 ... (LXI r(SP)) | [BC: 0x0000, DE: 0x0000, HL: 0x0000, A: 0x00, SP: 0x0000, C: 0, P: 0, AC: 0, Z: 0, S: 0]
areum (0x01ae): e6 00 ... (ANI data(8)) | [BC: 0x0000, DE: 0x0000, HL: 0x0000, A: 0x00, SP: 0x07ad, C: 0, P: 0, AC: 0, Z: 0, S: 0]

...

areum (0x0149): cd 05 00 ... (CALL addr) | [BC: 0xaa09, DE: 0x0174, HL: 0xaaaa, A: 0xaa, SP: 0xfffc, C: 0, P: 1, AC: 1, Z: 1, S: 0]
areum (0x0005): d3 00 ... (OUT data(8)) | [BC: 0xaa09, DE: 0x0174, HL: 0xaaaa, A: 0xaa, SP: 0xfffa, C: 0, P: 1, AC: 1, Z: 1, S: 0]


 CPU IS OPERATIONAL
areum (0x0007): c9 ... (RET) | [BC: 0xaa09, DE: 0x0174, HL: 0xaaaa, A: 0xaa, SP: 0xfffa, C: 0, P: 1, AC: 1, Z: 1, S: 0]
areum (0x014c): d1 ... (POP rp(D, E)) | [BC: 0xaa09, DE: 0x0174, HL: 0xaaaa, A: 0xaa, SP: 0xfffc, C: 0, P: 1, AC: 1, Z: 1, S: 0]
areum (0x014d): c9 ... (RET) | [BC: 0xaa09, DE: 0xaaaa, HL: 0xaaaa, A: 0xaa, SP: 0xfffe, C: 0, P: 1, AC: 1, Z: 1, S: 0]
areum (0x0000): 76 ... (HLT) | [BC: 0xaa09, DE: 0xaaaa, HL: 0xaaaa, A: 0xaa, SP: 0x0000, C: 0, P: 1, AC: 1, Z: 1, S: 0]
areum (0x0001): emulation finished.
```

## References

- [Emulator 101: 8080 reference](http://www.emulator101.com/reference/8080-by-opcode.html)
- [Intel 8080 Microcomputer Systems: User's Manual](https://www.amazon.com/INTEL-MICROCOMPUTER-SYSTEMS-USERS-MANUAL/dp/B000HVSJKU)
- [A Visual Guide to the Gameboy's Half-Carry Flag](https://robdor.com/2016/08/10/gameboy-emulator-half-carry-flag/)
- [Retrocomputing Stack Exchange: Test emulated 8080 CPU without an OS?](https://retrocomputing.stackexchange.com/questions/9361/test-emulated-8080-cpu-without-an-os)
- [Stack Overflow: CPU Emulation and locking to a specific clock speed](https://stackoverflow.com/questions/112439/cpu-emulation-and-locking-to-a-specific-clock-speed)
- [Stack Overflow: How do emulators work and how are they written?](https://stackoverflow.com/questions/448673/how-do-emulators-work-and-how-are-they-written)


## License

MIT License