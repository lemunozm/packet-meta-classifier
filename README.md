# Generic Packet Classifier (gpc)
A customizable packet classifier for any protocol stack.

## Features
- Generic: The classifier can be used for any purpose with any rules: e.g: internet, radio, bluetooth or yours.
- Easy: Implement an analyzer following few simple traits.
- Safety: The API forces a strict way of programming analyzers, reducing the human error in the process. Also, Thanks to *rust* inherit safety: no obfuscated coredumps.
- Fast: Rule analysis optimization: the packet will be gradually analyzed for the rules that require it.
- Rules with nested operators (not, and, or).
- Dependent analyzers: Chain different analyzer for diferent protocols.
- Flow support: Follow the state of your packet through their flows.
- Easy testing: Fill few properties on a struct and run the test.
- Pretty logs: Concised, with useful information, and full of colour!

### Current internet analyzers implemented
The following analyzers are implemented for [gpc-internet](gpc-internal),
an instantiation of `gpc` for internet protocol stack:
- Ip (v4/v6)
- Tcp
