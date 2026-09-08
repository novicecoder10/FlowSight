// Links the real parser by including the translation unit, so tests exercise the
// shipped code (including its file-scope ring buffer) rather than a copy.
#include "../cpp-sniffer/sniffer.cpp"
#include <cassert>
#include <iostream>

static int failures = 0;
static void check(bool ok, const std::string& what) {
    std::cout << (ok ? "  PASS  " : "  FAIL  ") << what << "\n";
    if (!ok) failures++;
}

// Ethernet + IPv4 + TCP, with `payload` as the TCP payload.
static std::vector<u_char> build_v4_tcp(uint16_t sport, uint16_t dport, const std::string& payload) {
    std::vector<u_char> p(14 + 20 + 20 + payload.size(), 0);
    p[12] = 0x08; p[13] = 0x00;                       // EtherType IPv4
    p[14] = 0x45;                                     // v4, IHL 5
    uint16_t total = 20 + 20 + payload.size();
    p[16] = total >> 8; p[17] = total & 0xff;
    p[23] = IPPROTO_TCP;
    p[26] = 10; p[27] = 0; p[28] = 0; p[29] = 1;      // src 10.0.0.1
    p[30] = 10; p[31] = 0; p[32] = 0; p[33] = 2;      // dst 10.0.0.2
    p[34] = sport >> 8; p[35] = sport & 0xff;
    p[36] = dport >> 8; p[37] = dport & 0xff;
    p[46] = 5 << 4;                                   // data offset 5 words
    memcpy(p.data() + 54, payload.data(), payload.size());
    return p;
}

// Ethernet + IPv6 + TCP
static std::vector<u_char> build_v6_tcp(uint16_t sport, uint16_t dport) {
    std::vector<u_char> p(14 + 40 + 20, 0);
    p[12] = 0x86; p[13] = 0xdd;                       // EtherType IPv6
    p[14] = 0x60;                                     // version 6
    p[18] = 0; p[19] = 20;                            // payload length
    p[20] = IPPROTO_TCP;                              // next header
    p[21] = 64;                                       // hop limit
    p[22] = 0x20; p[23] = 0x01;                       // src 2001::1
    p[37] = 1;
    p[38] = 0x20; p[39] = 0x01;                       // dst 2001::2
    p[53] = 2;
    p[54] = sport >> 8; p[55] = sport & 0xff;
    p[56] = dport >> 8; p[57] = dport & 0xff;
    p[66] = 5 << 4;
    return p;
}

static bool feed(const std::vector<u_char>& pkt, unsigned int caplen, PacketRecord& out) {
    struct pcap_pkthdr h{};
    h.caplen = caplen;
    h.len = caplen;
    CaptureContext ctx{14};
    packet_handler(reinterpret_cast<u_char*>(&ctx), &h, pkt.data());
    return g_ring_buffer.pop(out);
}

int main() {
    PacketRecord rec{};

    std::cout << "\n[#4] TLS SNI newline/comma injection\n";
    {
        char m[256];
        sanitize_meta("app=TLS;sni=evil\n[IPFIX] src_ip=1.2.3.4,dst_ip=9.9.9.9,proto=TCP", m, sizeof(m));
        std::string got(m);
        check(got.find('\n') == std::string::npos, "newline stripped (cannot forge a second record)");
        check(got.find(',') == std::string::npos, "comma stripped (cannot forge extra fields)");
    }

    std::cout << "\n[#6] meta buffer always NUL-terminated\n";
    {
        char m[256];
        memset(m, 'X', sizeof(m));
        sanitize_meta(std::string(4000, 'A'), m, sizeof(m));
        check(m[255] == '\0', "oversized metadata still terminated at m[255]");
        check(strlen(m) == 255, "truncated to exactly capacity-1");
    }

    std::cout << "\n[#5] truncated transport header (out-of-bounds read)\n";
    {
        auto pkt = build_v4_tcp(1234, 80, "");
        // Claim only the IP header was captured; the TCP header is absent.
        bool got = feed(pkt, 14 + 20, rec);
        check(got && rec.src_port == 0 && rec.dst_port == 0,
              "no port read from a capture truncated before the TCP header");
    }

    std::cout << "\n[#7] IPv6 port parsing\n";
    {
        auto pkt = build_v6_tcp(51000, 443);
        bool got = feed(pkt, pkt.size(), rec);
        check(got && rec.src_port == 51000 && rec.dst_port == 443,
              "IPv6 TCP ports parsed (was always 0/0)");
        check(got && rec.proto == IPPROTO_TCP, "IPv6 upper-layer protocol resolved");
    }

    std::cout << "\n[regression] IPv4 HTTP metadata still extracted\n";
    {
        auto pkt = build_v4_tcp(40000, 80, "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n");
        bool got = feed(pkt, pkt.size(), rec);
        check(got && rec.dst_port == 80, "IPv4 ports still parsed");
        check(got && std::string(rec.meta).find("host=example.test") != std::string::npos,
              "HTTP host still extracted");
    }

    std::cout << (failures ? "\n=== SNIFFER TESTS FAILED ===\n" : "\n=== SNIFFER TESTS PASSED ===\n");
    return failures ? 1 : 0;
}
