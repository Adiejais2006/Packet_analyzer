# DPI Engine: A C++ Packet Inspector

A small deep packet inspection tool that reads a Wireshark capture, works out which application each connection belongs to, drops traffic that matches your rules, and writes everything else to a new capture file.

This guide is meant to be read before the source. It starts with the networking basics, then follows one packet through both the single-threaded and the multi-threaded builds, so the code should feel familiar by the time you open it.

## Contents

1. [Why DPI exists](#1-why-dpi-exists)
2. [Networking primer](#2-networking-primer)
3. [What this project does](#3-what-this-project-does)
4. [Repository layout](#4-repository-layout)
5. [Single-threaded walkthrough](#5-single-threaded-walkthrough)
6. [Multi-threaded pipeline](#6-multi-threaded-pipeline)
7. [Component reference](#7-component-reference)
8. [Pulling the SNI out of a Client Hello](#8-pulling-the-sni-out-of-a-client-hello)
9. [Blocking logic](#9-blocking-logic)
10. [Build and run](#10-build-and-run)
11. [Reading the report](#11-reading-the-report)
12. [Ideas for extending it](#12-ideas-for-extending-it)

---

## 1. Why DPI exists

A basic firewall makes decisions from packet headers: who sent this, who is it for, which port. **Deep Packet Inspection** goes further and reads the data carried inside the packet, which lets a network device recognise *what* is being transmitted rather than just *where* it is going.

Common places you will find it:

- **Internet providers** shaping or restricting particular services such as file sharing
- **Company networks** keeping social media off work machines
- **Family filters** hiding unsuitable sites from children
- **Security tools** looking for signs of malware or intrusion

At a high level, this project does the following:

```
  capture.pcap ──►  DPI Engine  ──►  filtered.pcap
                        │
                        ├─ recognises the app behind each flow
                        ├─ drops flows that match a rule
                        └─ prints a summary report
```

---

## 2. Networking primer

### Layers

Network communication is organised into layers, each handling one job. Only four of them matter here:

```
 L7  Application   HTTP, TLS, DNS           what is being said
 L4  Transport     TCP, UDP                 how it is delivered
 L3  Network       IP                       where it is routed to
 L2  Data link     Ethernet / MAC           who is next door
```

### Packets are nested

Each layer wraps the layer above it in its own header, much like a parcel inside a box inside a larger box:

```
+--------------------------------------------------------------+
| Ethernet header (14 B)                                       |
|  +--------------------------------------------------------+  |
|  | IP header (20 B)                                       |  |
|  |  +--------------------------------------------------+  |  |
|  |  | TCP header (20 B)                                |  |  |
|  |  |  +--------------------------------------------+  |  |  |
|  |  |  | Payload: e.g. a TLS Client Hello           |  |  |  |
|  |  |  +--------------------------------------------+  |  |  |
|  |  +--------------------------------------------------+  |  |
|  +--------------------------------------------------------+  |
+--------------------------------------------------------------+
```

### Identifying a connection: the five-tuple

Five values pin down a single conversation between two programs:

| Value | Sample | Role |
|-------|--------|------|
| Source IP | `192.168.1.100` | the sender's address |
| Destination IP | `172.217.14.206` | the receiver's address |
| Source port | `54321` | the sender's temporary port |
| Destination port | `443` | the service being contacted (443 is HTTPS) |
| Protocol | TCP (6) | transport protocol in use |

Every packet sharing the same five values belongs to the same **flow**. That is what lets the engine keep state per connection, and it is why blocking has to apply to the whole flow: dropping only some packets of a connection accomplishes nothing useful.

### Server Name Indication (SNI)

When a browser opens `https://www.youtube.com`, its first message is a TLS **Client Hello**. That message carries the requested hostname in an extension called SNI, and it is sent *before* encryption begins, because the server needs the name to choose the right certificate.

```
Client Hello
 ├─ TLS version
 ├─ 32 random bytes
 ├─ list of cipher suites
 └─ extensions
     └─ server_name (SNI)
         └─ "www.youtube.com"      <- this is what we read
```

The payload of an HTTPS session is encrypted, but the name of the site being visited is exposed in the very first packet. The rest of this project depends on that fact.

---

## 3. What this project does

```
 +-------------+      +------------------+      +--------------+
 | input.pcap  | ───► |    DPI Engine    | ───► | output.pcap  |
 | (Wireshark) |      |  parse           |      | (forwarded   |
 +-------------+      |  classify        |      |  packets)    |
                      |  block           |      +--------------+
                      |  report          |
                      +------------------+
```

There are two builds that share the same core code:

| Build | Entry point | Best for |
|-------|-------------|----------|
| Single-threaded | `src/main_working.cpp` | learning how it works, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | large captures where throughput matters |

---

## 4. Repository layout

```
packet_analyzer/
├── include/
│   ├── pcap_reader.h           read PCAP files
│   ├── packet_parser.h         decode Ethernet / IP / TCP / UDP
│   ├── sni_extractor.h         pull hostnames from TLS and HTTP
│   ├── types.h                 FiveTuple, AppType and friends
│   ├── rule_manager.h          blocking rules (multi-threaded build)
│   ├── connection_tracker.h    per-flow state (multi-threaded build)
│   ├── load_balancer.h         load-balancer thread
│   ├── fast_path.h             fast-path worker thread
│   ├── thread_safe_queue.h     blocking queue shared between threads
│   └── dpi_engine.h            top-level coordinator
│
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp               helpers such as sniToAppType
│   ├── main_working.cpp        single-threaded program
│   ├── dpi_mt.cpp              multi-threaded program
│   └── ...                     supporting code
│
├── generate_test_pcap.py       builds a sample capture
├── test_dpi.pcap               sample capture with mixed traffic
└── README.md
```

---

## 5. Single-threaded walkthrough

To see the whole idea in one place, follow a single packet through `main_working.cpp`.

### Stage 1: open the capture

```cpp
PcapReader reader;
reader.open("capture.pcap");
```

The reader opens the file in binary mode, consumes the 24-byte global header, and checks the magic number to confirm the file really is a PCAP.

The file is laid out as one header followed by a repeating pattern:

```
 [ global header  24 B ]
 [ packet header  16 B ][ packet bytes ... ]
 [ packet header  16 B ][ packet bytes ... ]
 [ ... ]
```

### Stage 2: pull out packets one by one

```cpp
while (reader.readNextPacket(raw)) {
    // raw.header: timestamp and lengths
    // raw.data:   the captured bytes
}
```

Each call reads a 16-byte record header, then reads `incl_len` bytes of packet data. It returns `false` once the file is exhausted.

### Stage 3: decode the headers

```cpp
PacketParser::parse(raw, parsed);
```

The parser walks the bytes from the outside in:

```
bytes  0-13   Ethernet
bytes 14-33   IPv4
bytes 34-53   TCP
bytes 54...   payload
```

and fills in a `ParsedPacket`:

```
src_mac / dest_mac   00:11:22:33:44:55 / aa:bb:cc:dd:ee:ff
src_ip / dest_ip     192.168.1.100 / 172.217.14.206
src_port/dest_port   54321 / 443
protocol             6 (TCP)
has_tcp              true
```

The fields it reads from each header:

```
Ethernet:  0-5 destination MAC | 6-11 source MAC | 12-13 EtherType (0x0800 = IPv4)
IPv4:      byte 0 version + header length | byte 8 TTL | byte 9 protocol
           12-15 source IP | 16-19 destination IP
TCP:       0-1 source port | 2-3 destination port | 4-7 sequence number
           8-11 ack number | byte 12 data offset | byte 13 flags
```

### Stage 4: find (or create) the flow

```cpp
FiveTuple tuple;
tuple.src_ip   = parseIP(parsed.src_ip);
tuple.dst_ip   = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];   // existing flow, or a fresh one
```

The flow table is an ordinary hash map from `FiveTuple` to `Flow`. Packets from the same conversation land on the same entry, so information learned from one packet (like the hostname) is available for every later one.

### Stage 5: look inside the payload

```cpp
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni      = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni);      // AppType::YOUTUBE
    }
}
```

Inside `SNIExtractor::extract` the steps are:

1. Confirm the payload is a TLS Client Hello (first byte `0x16`, sixth byte `0x01`).
2. Step over the version, random value, session ID, cipher suites and compression list.
3. Scan the extensions until the one with type `0x0000` turns up.
4. Read the hostname from inside it.

Section 8 goes through this byte by byte. Once the hostname is known, `sniToAppType` in `types.cpp` turns it into an app label with simple substring checks:

```cpp
if (sni.find("youtube") != std::string::npos) return AppType::YOUTUBE;
```

### Stage 6: consult the rules

```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

Internally the check runs through three lists:

```cpp
if (blocked_ips.count(src_ip))   return true;   // banned source address
if (blocked_apps.count(app))     return true;   // banned application
for (const auto& d : blocked_domains)           // banned hostname fragment
    if (sni.find(d) != std::string::npos) return true;
return false;
```

### Stage 7: forward or discard

```cpp
if (flow.blocked) {
    ++dropped;                     // simply never written out
} else {
    ++forwarded;
    output.write(packet_header);   // keep the packet
    output.write(packet_data);
}
```

### Stage 8: summarise

When the input is exhausted, the program tallies packets per application and prints something like:

```
YouTube   150 packets (15%)
Facebook   80 packets (8%)
...
```

---

## 6. Multi-threaded pipeline

`dpi_mt.cpp` keeps the same logic but splits it across threads so that several packets can be processed simultaneously.

### The layout

```
                        Reader (main thread)
                                │
                     hash(5-tuple) % num_lbs
                    ┌───────────┴───────────┐
                    ▼                       ▼
                  LB 0                     LB 1
                    │                       │
            hash % fps_per_lb       hash % fps_per_lb
              ┌─────┴─────┐          ┌─────┴─────┐
              ▼           ▼          ▼           ▼
            FP 0        FP 1        FP 2        FP 3
              └─────┬─────┴──────────┴─────┬─────┘
                    ▼                       
              output queue
                    │
                    ▼
              writer thread ──► output.pcap
```

Three kinds of worker are involved:

- **Reader**: parses the input file and hands each packet to a load balancer.
- **Load balancers (LBs)**: fan packets out to fast paths.
- **Fast paths (FPs)**: do the real work, meaning flow lookup, SNI extraction and rule checks.

### Why the hashing must be consistent

Choosing a worker by hashing the five-tuple means every packet in a connection takes the same route:

```
Connection 192.168.1.100:54321 → 142.250.185.206:443

  SYN           ─► hash ─► FP2
  SYN-ACK       ─► hash ─► FP2
  Client Hello  ─► hash ─► FP2
  application   ─► hash ─► FP2
```

Because one FP sees the entire conversation, it can keep its own private flow table with no locking, and it always knows whether the flow has already been identified or blocked.

### What each thread does

**Reader**

```cpp
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);
    size_t lb = hash(pkt.tuple) % num_lbs;
    lbs_[lb]->queue().push(pkt);
}
```

**Load balancer**

```cpp
void LoadBalancer::run() {
    while (running_) {
        auto pkt = input_queue_.pop();               // blocks until work arrives
        size_t fp = hash(pkt.tuple) % num_fps_;
        fps_[fp]->queue().push(pkt);
    }
}
```

**Fast path**

```cpp
void FastPath::run() {
    while (running_) {
        auto pkt = input_queue_.pop();
        Flow& flow = flows_[pkt.tuple];              // private table, no lock needed
        classifyFlow(pkt, flow);                     // SNI / Host extraction

        if (rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni))
            stats_->dropped++;
        else
            output_queue_->push(pkt);
    }
}
```

**Writer**

```cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();
        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

### The queue that ties it together

All hand-offs go through a blocking queue built on a mutex and a condition variable:

```cpp
template<typename T>
class TSQueue {
    std::queue<T>           queue_;
    std::mutex              mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;

    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();              // wake one sleeping consumer
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&]{ return !queue_.empty(); });
        T item = queue_.front();
        queue_.pop();
        return item;
    }
};
```

- The **mutex** guarantees only one thread touches the queue at a time.
- The **condition variable** lets an idle consumer sleep instead of spinning, and be woken as soon as something is pushed.

---

## 7. Component reference

### `pcap_reader`

Reads capture files saved by Wireshark or tcpdump.

```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;    // 0xa1b2c3d4 marks a PCAP file
    uint16_t version_major;   // normally 2
    uint16_t version_minor;   // normally 4
    uint32_t snaplen;         // largest packet stored
    uint32_t network;         // link type, 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;          // capture time, seconds
    uint32_t ts_usec;         // capture time, microseconds
    uint32_t incl_len;        // bytes actually stored
    uint32_t orig_len;        // size on the wire
};
```

Main functions: `open(filename)`, `readNextPacket(raw)`, `close()`.

### `packet_parser`

Turns raw bytes into named fields.

```cpp
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parseEthernet(...);   // MAC addresses, EtherType
    parseIPv4(...);       // addresses, protocol, TTL
    parseTCP(...);        // ports, flags, sequence numbers
    // or parseUDP(...)   // ports
}
```

**A note on byte order.** Network protocols send the most significant byte first (big-endian), while many CPUs store it the other way round. Multi-byte values must therefore be converted after reading:

```cpp
uint16_t port = ntohs(*(uint16_t*)(data + offset));   // 16-bit
uint32_t seq  = ntohl(*(uint32_t*)(data + offset));   // 32-bit
```

### `sni_extractor`

Recovers hostnames from the two protocols where they appear in clear text.

```cpp
// HTTPS: hostname from the TLS Client Hello
std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length);

// HTTP: hostname from the Host header of a plain request
std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length);
```

The HTTP version checks the payload starts with a method (`GET`, `POST`, ...), finds the `Host:` line, and returns the value up to the end of that line.

### `types`

Shared definitions.

```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    bool operator==(const FiveTuple& other) const;
};

enum class AppType { UNKNOWN, HTTP, HTTPS, DNS, GOOGLE, YOUTUBE, FACEBOOK /* ... */ };

AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube")  != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) return AppType::FACEBOOK;
    // ...
}
```

---

## 8. Pulling the SNI out of a Client Hello

### Where the Client Hello sits in the handshake

```
 Browser                                   Server
    │  ── Client Hello (SNI: www.youtube.com) ─►  │
    │  ◄─ Server Hello + certificate ───────────  │
    │  ── key exchange ─────────────────────────► │
    │  ◄═══════ encrypted traffic ═══════════════►│
```

Everything after the handshake is encrypted, so the Client Hello is our one opportunity to read the hostname.

### Byte layout

```
 0        content type   0x16 = handshake
 1-2      record version
 3-4      record length
 ── handshake layer ──
 5        handshake type 0x01 = Client Hello
 6-8      handshake length
 ── Client Hello body ──
 9-10     client version
 11-42    random (32 bytes)
 43       session ID length (N)
 44..     session ID (N bytes)
 ...      cipher suites (2-byte length + list)
 ...      compression methods (1-byte length + list)
 ...      extensions length (2 bytes)
 ...      extensions, each: type (2) | length (2) | data
 ── inside the SNI extension (type 0x0000) ──
          list length (2) | name type (1, 0 = hostname) | name length (2) | name
```

### Simplified extraction code

```cpp
std::optional<std::string> SNIExtractor::extract(const uint8_t* p, size_t len) {
    if (p[0] != 0x16) return std::nullopt;     // not a handshake record
    if (p[5] != 0x01) return std::nullopt;     // not a Client Hello

    size_t pos = 43;                           // position of the session ID length

    pos += 1 + p[pos];                         // skip session ID

    uint16_t suites = readUint16BE(p + pos);   // skip cipher suites
    pos += 2 + suites;

    pos += 1 + p[pos];                         // skip compression methods

    uint16_t ext_total = readUint16BE(p + pos);
    pos += 2;
    size_t end = pos + ext_total;

    while (pos + 4 <= end) {                   // walk the extensions
        uint16_t type = readUint16BE(p + pos);
        uint16_t size = readUint16BE(p + pos + 2);
        pos += 4;

        if (type == 0x0000) {                  // server_name
            uint16_t name_len = readUint16BE(p + pos + 3);
            return std::string((const char*)(p + pos + 5), name_len);
        }
        pos += size;                           // not SNI, move on
    }
    return std::nullopt;                       // no SNI present
}
```

The real implementation should also confirm that `pos` never runs past `len` before each read, since captured packets can be truncated or malformed.

---

## 9. Blocking logic

### Three kinds of rule

| Rule | Example | Effect |
|------|---------|--------|
| IP | `192.168.1.50` | drops everything sent from that address |
| App | `YouTube` | drops every flow classified as that application |
| Domain | `tiktok` | drops any flow whose SNI contains that text |

### Decision order

```
   packet arrives
        │
        ▼
  source IP banned? ── yes ──► DROP
        │ no
        ▼
  app type banned?  ── yes ──► DROP
        │ no
        ▼
  SNI matches a banned domain? ── yes ──► DROP
        │ no
        ▼
     FORWARD
```

### Rules apply per flow, not per packet

The application cannot be identified until the Client Hello shows up, so the opening packets of every connection are unavoidably forwarded. After the hostname is seen and matches a rule, the flow is flagged and everything afterwards is discarded:

```
Connection to YouTube
  1  SYN                → no SNI yet     → forward
  2  SYN-ACK            → no SNI yet     → forward
  3  ACK                → no SNI yet     → forward
  4  Client Hello       → SNI = www.youtube.com
                          app = YOUTUBE (banned)
                          flag flow as blocked → drop
  5+ every later packet → flow is flagged → drop
```

The client never receives a Server Hello, so its connection attempt stalls and eventually times out.

---

## 10. Build and run

### Requirements

- Linux or macOS
- `g++` or `clang++` with C++17 support
- No third-party libraries

### Building

Single-threaded:

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
```

Multi-threaded:

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
```

### Running

Without any rules:

```bash
./dpi_engine test_dpi.pcap output.pcap
```

With rules:

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

Choosing the thread counts (multi-threaded build only):

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# 4 load balancers x 4 fast paths each = 16 fast-path workers
```

### Sample data

```bash
python3 generate_test_pcap.py     # writes test_dpi.pcap
```

---

## 11. Reading the report

An example run with two rules active:

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
```

| Section | What it tells you |
|---------|-------------------|
| Header | how many LB and FP threads were started |
| Rules | which block rules are active for this run |
| Total Packets / Bytes | how much was read from the input file |
| Forwarded | packets written to the output capture |
| Dropped | packets discarded because of a rule |
| Thread Statistics | how evenly work was spread across workers |
| Application Breakdown | what each flow was classified as |
| Detected Domains | the hostnames that were actually extracted |

The uneven thread numbers above (FP1 and FP2 idle) are normal for a tiny capture. With only a few distinct flows, the hash simply has little to spread around.

---

## 12. Ideas for extending it

1. **More app signatures.** Add another pattern in `types.cpp`:
   ```cpp
   if (sni.find("twitch") != std::string::npos) return AppType::TWITCH;
   ```

2. **Throttling instead of dropping.** Delay packets from a flow rather than discarding them:
   ```cpp
   if (shouldThrottle(flow)) std::this_thread::sleep_for(std::chrono::milliseconds(10));
   ```

3. **A live statistics view.** A background thread that prints counters once a second:
   ```cpp
   void statsThread() {
       while (running) { printStats(); std::this_thread::sleep_for(std::chrono::seconds(1)); }
   }
   ```

4. **QUIC / HTTP/3.** These run over UDP port 443, and the hostname sits in the Initial packet, which is protected differently and needs extra decryption logic.

5. **Saved rule sets.** Write rules to a file and reload them at startup.

---

## Wrap-up

Working through this project touches on:

1. Decoding network protocols from raw bytes
2. Inspecting traffic that is otherwise encrypted
3. Tracking connection state across packets
4. Scaling work across a pool of threads
5. The producer-consumer pattern with thread-safe queues

The central observation is that HTTPS still reveals its destination hostname in the opening handshake, and that is enough for a network operator to recognise and control which applications are in use.

If you are reading the code for the first time, begin with `main_working.cpp`, since it follows the stages in section 5 almost line for line. Move on to `dpi_mt.cpp` once that makes sense; the extra material is just the threading described in section 6.