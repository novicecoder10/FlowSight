# FlowSight packet sniffer

The capture half of FlowSight. Reads frames with libpcap into a 256MB ring buffer,
extracts L3/L4 fields and light L7 metadata (HTTP Host, TLS SNI, SSH banners), and writes
one line per packet to **stdout**. The server (`src/index.ts`) spawns it and parses those
lines; **stderr** carries status and errors, which the server turns into the dashboard's
capture-health badge.

It is a standalone program, so it can be built and run on its own — useful when
diagnosing a capture problem without the dashboard in the way.

## Build

Needs `libpcap-dev` and OpenSSL:

```sh
sudo apt install libpcap-dev libssl-dev
cd cpp-sniffer
make                 # produces ./packet_sniffer
make clean           # remove objects and the binary
```

Use the **Makefile**, not `CMakeLists.txt`. The CMake path emits into `build/`, and
`startSniffer()` in the server looks for `cpp-sniffer/packet_sniffer` (override with
`SNIFFER_BIN`).

## Capability

Raw capture needs `CAP_NET_RAW`. Grant it to the binary once per build:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip packet_sniffer
```

**A rebuild drops the capability** — file capabilities do not survive replacing the file.
The only symptom is this on stderr, with an empty packet history in the dashboard:

```
[FlowSight] Couldn't activate interface any (code -8): socket: Operation not permitted
```

Re-run `setcap` after every `make`.

## Run

```sh
./packet_sniffer                 # capture on 'any' (the default)
./packet_sniffer enp6s0          # capture one interface
sudo ./packet_sniffer enp6s0     # alternative to setcap; then run the dashboard as
                                 # a normal user, never under sudo
```

The single optional argument is the interface name. Under the dashboard this comes from
`SNIFFER_DEVICE`, and you do not start the sniffer yourself — `npm start` spawns it.

To watch the raw feed, or to check that capture works before involving the server:

```sh
./packet_sniffer enp6s0 | head -20      # stdout: parsed packets
./packet_sniffer enp6s0 > /dev/null     # stderr only: status and errors
```

## Output format

One line per packet on stdout:

```
[IPFIX] src_ip=…,dst_ip=…,proto=…,src_port=…,dst_port=…,meta=…,bytes=…
```

This line is the entire contract between the two processes. Changing the `std::printf`
in `sniffer.cpp` requires a matching change to `parsePacket()` in `src/index.ts`.
`meta` is attacker-influenced (it carries hostnames and SNI off the wire), so it is
sanitised at the source: commas and newlines are stripped and the buffer is always
NUL-terminated, otherwise a crafted hostname could forge extra fields or a second
record. `tests/sniffer_test.cpp` covers that.

## Files

```
main.cpp     entrypoint, interface argument
sniffer.cpp  capture loop, ring buffer, L7 metadata extraction, output
utils.cpp    parsing helpers
```
