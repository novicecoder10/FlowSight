#include "sniffer.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

// ── Ring Buffer & Record Definitions for Zero-Copy Line-Rate Processing ──
constexpr size_t RING_CAPACITY = 262144; // 256k slot lockless ring buffer

struct PacketRecord {
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t bytes;
    uint8_t  proto; // 6 = TCP, 17 = UDP, 1 = ICMP, 0 = Other
    char meta[256];
};

struct LockFreeRing {
    PacketRecord buffer[RING_CAPACITY];
    alignas(64) std::atomic<size_t> head{0};
    alignas(64) std::atomic<size_t> tail{0};

    bool push(const PacketRecord& rec) {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % RING_CAPACITY;
        if (next_head == tail.load(std::memory_order_acquire)) {
            return false; // Ring buffer full (drop to prevent capture stall)
        }
        buffer[current_head] = rec;
        head.store(next_head, std::memory_order_release);
        return true;
    }

    bool pop(PacketRecord& rec) {
        size_t current_tail = tail.load(std::memory_order_relaxed);
        if (current_tail == head.load(std::memory_order_acquire)) {
            return false; // Empty
        }
        rec = buffer[current_tail];
        tail.store((current_tail + 1) % RING_CAPACITY, std::memory_order_release);
        return true;
    }
};

static LockFreeRing g_ring_buffer;
static std::atomic<bool> g_running{true};
static std::atomic<uint64_t> g_packets_captured{0};
static std::atomic<uint64_t> g_packets_dropped{0};

// ── Fast IP & Hex Formatting Helpers ──
inline void fast_ipv4_to_buf(uint32_t ip_net_order, char* out) {
    uint32_t ip = ntohl(ip_net_order);
    std::sprintf(out, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

std::string calculate_sha256(const u_char* data, int len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    static const char hex[] = "0123456789abcdef";
    std::string hash_str;
    hash_str.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hash_str += hex[hash[i] >> 4];
        hash_str += hex[hash[i] & 0x0f];
    }
    return hash_str;
}

std::string md5_hex(const std::string& value) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(value.data()), value.size(), digest);
    char buf[33];
    for (int i = 0; i < 16; ++i) {
        std::sprintf(buf + i * 2, "%02x", digest[i]);
    }
    return std::string(buf, 32);
}

std::string sha256_hex(const std::string& value) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(value.data()), value.size(), digest);
    char buf[65];
    for (int i = 0; i < 32; ++i) {
        std::sprintf(buf + i * 2, "%02x", digest[i]);
    }
    return std::string(buf, 64);
}

inline bool greased(uint16_t value) {
    return (value & 0x0f0f) == 0x0a0a;
}

inline uint16_t read_u16(const u_char* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

std::string join_numbers(const std::vector<uint16_t>& values, char separator = '-') {
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index) output << separator;
        output << values[index];
    }
    return output.str();
}

std::string join_hex(const std::vector<uint16_t>& values) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (size_t index = 0; index < values.size(); ++index) {
        if (index) output << '-';
        output << std::setw(4) << values[index];
    }
    return output.str();
}

std::string header_value(const std::string& data, const std::string& name) {
    size_t start = 0;
    while (start < data.size()) {
        size_t end = data.find('\n', start);
        if (end == std::string::npos) end = data.size();
        std::string line = data.substr(start, end - start);
        if (line.size() >= name.size() && std::equal(name.begin(), name.end(), line.begin(), [](char left, char right) {
            return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
        })) {
            size_t separator = line.find(':');
            if (separator != std::string::npos) {
                size_t value_start = line.find_first_not_of(" \t", separator + 1);
                return value_start == std::string::npos ? "" : line.substr(value_start);
            }
        }
        start = end + 1;
    }
    return "";
}

bool looks_like_http(const std::string& data) {
    static const char* methods[] = {"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1.", "HTTP/2"};
    for (const char* method : methods) if (data.rfind(method, 0) == 0) return true;
    return false;
}

std::string extract_http_metadata(const u_char* payload, int payload_len) {
    std::string data(reinterpret_cast<const char*>(payload), payload_len);
    size_t line_end = data.find('\n');
    std::string first_line = data.substr(0, line_end == std::string::npos ? data.size() : line_end);
    std::ostringstream meta;
    meta << "app=HTTP";
    size_t first_space = first_line.find(' ');
    size_t second_space = first_space == std::string::npos ? std::string::npos : first_line.find(' ', first_space + 1);
    if (first_line.rfind("HTTP/", 0) == 0 && first_space != std::string::npos) {
        meta << ";status=" << first_line.substr(first_space + 1, 3);
    } else if (first_space != std::string::npos) {
        meta << ";method=" << first_line.substr(0, first_space)
             << ";url=" << first_line.substr(first_space + 1, second_space - first_space - 1);
    }
    std::string host = header_value(data, "Host");
    std::string referer = header_value(data, "Referer");
    std::string user_agent = header_value(data, "User-Agent");
    if (!host.empty()) meta << ";host=" << host;
    if (!referer.empty()) meta << ";referer=" << referer;
    if (!user_agent.empty()) meta << ";user_agent=" << user_agent;
    return meta.str();
}

std::string extract_tls_metadata(const u_char* payload, int payload_len) {
    if (payload_len < 9 || payload[0] != 0x16) return "app=TLS";
    uint8_t handshake_type = payload[5];
    const u_char* body = payload + 9;
    int body_len = payload_len - 9;
    if (handshake_type != 1 && handshake_type != 2) return "app=TLS";
    if (body_len < 35) return "app=TLS";
    uint16_t version = read_u16(body);
    int offset = 34;
    int session_length = body[34];
    offset += 1 + session_length;
    if (offset + 2 > body_len) return "app=TLS";
    uint16_t cipher_length = read_u16(body + offset);
    offset += 2;
    std::vector<uint16_t> ciphers;
    for (int index = 0; index + 1 < cipher_length && offset + index + 1 < body_len; index += 2) {
        uint16_t cipher = read_u16(body + offset + index);
        if (!greased(cipher)) ciphers.push_back(cipher);
    }
    offset += cipher_length;
    if (offset >= body_len) return "app=TLS";
    if (handshake_type == 1) offset += 1 + body[offset];
    else offset += 3;
    if (offset + 2 > body_len) return "app=TLS";
    uint16_t extension_length = read_u16(body + offset);
    offset += 2;
    int extension_end = std::min(body_len, offset + static_cast<int>(extension_length));
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> curves;
    std::vector<uint16_t> points;
    std::string sni;
    while (offset + 4 <= extension_end) {
        uint16_t type = read_u16(body + offset);
        uint16_t length = read_u16(body + offset + 2);
        offset += 4;
        if (offset + length > extension_end) break;
        if (!greased(type)) extensions.push_back(type);
        if (type == 0 && length >= 5 && body[offset + 2] == 0) {
            int name_length = read_u16(body + offset + 3);
            if (offset + 5 + name_length <= extension_end) sni.assign(reinterpret_cast<const char*>(body + offset + 5), name_length);
        } else if (type == 10 && length >= 2) {
            int list_length = read_u16(body + offset);
            for (int index = 2; index + 1 < list_length && offset + index + 1 < extension_end; index += 2) {
                uint16_t curve = read_u16(body + offset + index);
                if (!greased(curve)) curves.push_back(curve);
            }
        } else if (type == 11 && length >= 1) {
            int list_length = body[offset];
            for (int index = 1; index < list_length && offset + index < extension_end; ++index) points.push_back(body[offset + index]);
        }
        offset += length;
    }
    std::string ja3 = join_numbers({version}, ',') + "," + join_numbers(ciphers) + "," + join_numbers(extensions) + "," + join_numbers(curves) + "," + join_numbers(points);
    std::ostringstream meta;
    meta << "app=TLS";
    if (!sni.empty()) meta << ";sni=" << sni;
    meta << ";" << (handshake_type == 1 ? "ja3=" : "ja3s=") << md5_hex(ja3);
    meta << ";" << (handshake_type == 1 ? "ja4=" : "ja4s=") << sha256_hex(join_hex(ciphers) + ":" + join_numbers(extensions)).substr(0, 12);
    return meta.str();
}

std::string extract_application_metadata(const u_char* payload, int payload_len, uint16_t src_port, uint16_t dst_port) {
    std::string data(reinterpret_cast<const char*>(payload), payload_len);
    if (looks_like_http(data) || src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080) return extract_http_metadata(payload, payload_len);
    if ((payload_len >= 1 && payload[0] == 0x16) || src_port == 443 || dst_port == 443) return extract_tls_metadata(payload, payload_len);
    std::string meta;
    if (src_port == 22 || dst_port == 22 || data.rfind("SSH-", 0) == 0) {
        meta = "app=SSH";
        if (data.rfind("SSH-", 0) == 0) meta += ";banner=" + data.substr(0, data.find_first_of("\r\n"));
    } else if (src_port == 25 || dst_port == 25 || src_port == 587 || dst_port == 587) {
        meta = "app=SMTP";
        size_t from_pos = data.find("From: ");
        size_t to_pos = data.find("To: ");
        size_t sub_pos = data.find("Subject: ");
        if (from_pos != std::string::npos) meta += "From=" + data.substr(from_pos, data.find('\n', from_pos) - from_pos) + "; ";
        if (to_pos != std::string::npos) meta += "To=" + data.substr(to_pos, data.find('\n', to_pos) - to_pos) + "; ";
        if (sub_pos != std::string::npos) meta += "Subject=" + data.substr(sub_pos, data.find('\n', sub_pos) - sub_pos) + "; ";
    } else if (src_port == 53 || dst_port == 53) {
        meta = "app=DNS;message=Query or response";
    } else if (src_port == 21 || dst_port == 21 || src_port == 20 || dst_port == 20) {
        meta = "app=FTP";
    } else if (src_port == 123 || dst_port == 123) {
        meta = "app=NTP";
    } else if (src_port == 3389 || dst_port == 3389) {
        meta = "app=RDP";
    } else {
        meta = "app=Other";
    }
    return meta;
}

// Metadata below is reconstructed from attacker-controlled bytes (HTTP headers, TLS
// SNI, SSH banners). The IPFIX line is comma/equals delimited and newline terminated,
// so any of those characters would let a crafted packet forge extra records or corrupt
// field parsing downstream. Reduce to a conservative printable set.
void sanitize_meta(const std::string& input, char* out, size_t out_size) {
    size_t written = 0;
    const size_t limit = out_size - 1;
    for (unsigned char character : input) {
        if (written >= limit) break;
        if (character < 0x20 || character > 0x7e) continue;   // control bytes, newlines, non-ASCII
        if (character == ',' || character == '\n' || character == '\r') continue; // field/record separators
        if (character == '"' || character == '\\') continue;  // quoting hazards downstream
        out[written++] = static_cast<char>(character);
    }
    out[written] = '\0';   // always terminated, unlike strncpy
}

void send_ipfix(const std::string& ipfix_data) {
    std::printf("[IPFIX] %s\n", ipfix_data.c_str());
}

struct CaptureContext {
    int link_offset;
};

// Universal Encapsulation & Dynamic Header Unzipper (VLAN, QinQ, MPLS, PPPoE, VN-Tag, Heuristic Scanner)
inline int find_ip_header_offset(const u_char* packet, unsigned int caplen, int initial_offset, uint8_t& out_version) {
    if (caplen < static_cast<unsigned int>(initial_offset + 20)) return -1;

    int offset = initial_offset;

    if (initial_offset == 14 && caplen >= 14) {
        uint16_t eth_type = read_u16(packet + 12);
        bool outer_loop = true;

        while (outer_loop && offset + 4 <= static_cast<int>(caplen)) {
            switch (eth_type) {
                case 0x8100: // 802.1Q VLAN Tag
                case 0x88A8: // 802.1ad QinQ S-Tag
                case 0x9100: // Legacy VLAN Tag
                case 0x9200:
                case 0x9300:
                    eth_type = read_u16(packet + offset + 2);
                    offset += 4;
                    break;

                case 0x8847: // MPLS Unicast
                case 0x8848: // MPLS Multicast
                {
                    // Scan stacked MPLS labels until Bottom-of-Stack (S-bit = 1)
                    while (offset + 4 <= static_cast<int>(caplen)) {
                        uint8_t bos_byte = packet[offset + 2];
                        offset += 4;
                        if (bos_byte & 0x01) { // S-bit is set (Last MPLS label)
                            break;
                        }
                    }
                    if (offset < static_cast<int>(caplen)) {
                        uint8_t first_nibble = (packet[offset] >> 4) & 0x0F;
                        if (first_nibble == 4 || first_nibble == 6) {
                            out_version = first_nibble;
                            return offset;
                        }
                    }
                    outer_loop = false;
                    break;
                }

                case 0x8864: // PPPoE Session Stage
                case 0x8863: // PPPoE Discovery Stage
                {
                    if (offset + 8 <= static_cast<int>(caplen)) {
                        uint16_t ppp_proto = read_u16(packet + offset + 6);
                        offset += 8;
                        if (ppp_proto == 0x0021) eth_type = 0x0800; // IPv4
                        else if (ppp_proto == 0x0057) eth_type = 0x86DD; // IPv6
                    } else {
                        outer_loop = false;
                    }
                    break;
                }

                case 0x8926: // Cisco VN-Tag
                    offset += 6;
                    if (offset + 2 <= static_cast<int>(caplen)) eth_type = read_u16(packet + offset - 2);
                    break;

                default:
                    outer_loop = false;
                    break;
            }
        }
    }

    // Direct IPv4/IPv6 check at calculated offset
    if (offset + 20 <= static_cast<int>(caplen)) {
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + offset);
        if (ip_hdr->ip_v == 4) {
            out_version = 4;
            return offset;
        } else if (ip_hdr->ip_v == 6 && offset + 40 <= static_cast<int>(caplen)) {
            const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(packet + offset);
            uint8_t nxt = ip6->ip6_nxt;
            if (nxt == IPPROTO_TCP || nxt == IPPROTO_UDP || nxt == IPPROTO_ICMPV6 || nxt == IPPROTO_ICMP || nxt == 0 || nxt == 43 || nxt == 44 || nxt == 47 || nxt == 50 || nxt == 51 || nxt == 59) {
                out_version = 6;
                return offset;
            }
        }
    }

    // Universal Heuristic Fallback Scanner: Scan payload up to 64 bytes forward for IPv4/IPv6 magic header
    for (int scan = initial_offset; scan <= std::min(64, static_cast<int>(caplen) - 20); ++scan) {
        const struct ip* candidate = reinterpret_cast<const struct ip*>(packet + scan);
        if (candidate->ip_v == 4) {
            int hlen = candidate->ip_hl * 4;
            uint16_t tot_len = ntohs(candidate->ip_len);
            if (hlen >= 20 && hlen <= 60 && tot_len >= hlen && tot_len <= 65535) {
                out_version = 4;
                return scan;
            }
        } else if (candidate->ip_v == 6 && scan + 40 <= static_cast<int>(caplen)) {
            const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(packet + scan);
            uint8_t nxt = ip6->ip6_nxt;
            if (nxt == IPPROTO_TCP || nxt == IPPROTO_UDP || nxt == IPPROTO_ICMPV6 || nxt == IPPROTO_ICMP || nxt == 0 || nxt == 43 || nxt == 44 || nxt == 47 || nxt == 50 || nxt == 51 || nxt == 59) {
                out_version = 6;
                return scan;
            }
        }
    }

    return -1;
}

inline bool is_ipv6_extension(uint8_t next) {
    return next == 0 || next == 43 || next == 44 || next == 51 || next == 60 || next == 135;
}

// Shared by the IPv4 and IPv6 paths. transport_offset is an absolute offset into the
// captured buffer; every read is bounded by caplen so a truncated capture cannot walk
// off the end.
inline void parse_transport(const u_char* packet, unsigned int caplen, int ip_offset, int transport_offset, uint8_t proto, PacketRecord& rec) {
    if (proto == IPPROTO_TCP) {
        if (caplen < static_cast<unsigned int>(transport_offset) + sizeof(struct tcphdr)) return;
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + transport_offset);
        rec.src_port = ntohs(tcp->th_sport);
        rec.dst_port = ntohs(tcp->th_dport);
        int data_offset = tcp->th_off * 4;
        if (data_offset < static_cast<int>(sizeof(struct tcphdr))) return;   // malformed
        int payload_start = transport_offset + data_offset;
        if (caplen <= static_cast<unsigned int>(payload_start)) return;
        int payload_len = static_cast<int>(caplen) - payload_start;
        std::string meta_str = extract_application_metadata(packet + payload_start, payload_len, rec.src_port, rec.dst_port);
        if (!meta_str.empty()) sanitize_meta(meta_str, rec.meta, sizeof(rec.meta));
    } else if (proto == IPPROTO_UDP) {
        if (caplen < static_cast<unsigned int>(transport_offset) + sizeof(struct udphdr)) return;
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(packet + transport_offset);
        rec.src_port = ntohs(udp->uh_sport);
        rec.dst_port = ntohs(udp->uh_dport);
        int payload_start = transport_offset + static_cast<int>(sizeof(struct udphdr));
        if (caplen <= static_cast<unsigned int>(payload_start)) return;
        int payload_len = static_cast<int>(caplen) - payload_start;
        std::string meta_str = extract_application_metadata(packet + payload_start, payload_len, rec.src_port, rec.dst_port);
        if (!meta_str.empty()) sanitize_meta(meta_str, rec.meta, sizeof(rec.meta));
    }
    (void)ip_offset;
}

// Fast Packet Capture Callback (Executes in nanoseconds per packet with Universal Header Unzipping)
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const auto* context = reinterpret_cast<const CaptureContext*>(user);
    int initial_offset = context ? context->link_offset : 14;

    uint8_t ip_version = 0;
    int offset = find_ip_header_offset(packet, header->caplen, initial_offset, ip_version);
    if (offset < 0) return; // Drop only non-IP corrupted noise

    PacketRecord rec;
    rec.bytes = header->len; // True wire length (for 100% accurate wire Mbps calculation)
    rec.src_port = 0;
    rec.dst_port = 0;
    rec.meta[0] = '\0';

    if (ip_version == 4) {
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + offset);
        inet_ntop(AF_INET, &(ip_hdr->ip_src), rec.src_ip, sizeof(rec.src_ip));
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), rec.dst_ip, sizeof(rec.dst_ip));
        rec.proto = ip_hdr->ip_p;

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        if (ip_hdr_len >= 20 && header->caplen >= static_cast<unsigned int>(offset + ip_hdr_len)) {
            parse_transport(packet, header->caplen, offset, offset + ip_hdr_len, ip_hdr->ip_p, rec);
        }
    } else if (ip_version == 6) {
        const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(packet + offset);
        inet_ntop(AF_INET6, &(ip6->ip6_src), rec.src_ip, sizeof(rec.src_ip));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), rec.dst_ip, sizeof(rec.dst_ip));

        // Walk the extension header chain to the real upper-layer protocol, then parse
        // ports and metadata exactly as for IPv4. Previously IPv6 stopped at the
        // addresses, leaving every v6 flow with ports 0 and no application metadata.
        int header_offset = offset + 40;
        uint8_t next = ip6->ip6_nxt;
        int hops = 0;
        while (hops++ < 8 && is_ipv6_extension(next)) {
            if (header->caplen < static_cast<unsigned int>(header_offset + 8)) break;
            uint8_t following = packet[header_offset];
            int ext_len;
            if (next == 44) {                    // Fragment header is a fixed 8 bytes
                ext_len = 8;
            } else if (next == 51) {             // Authentication Header: (len + 2) * 4
                ext_len = (packet[header_offset + 1] + 2) * 4;
            } else {
                ext_len = (packet[header_offset + 1] + 1) * 8;
            }
            if (ext_len <= 0) break;
            header_offset += ext_len;
            next = following;
        }
        rec.proto = next;
        if (header->caplen >= static_cast<unsigned int>(header_offset)) {
            parse_transport(packet, header->caplen, offset, header_offset, next, rec);
        }
    }

    g_packets_captured.fetch_add(1, std::memory_order_relaxed);
    if (!g_ring_buffer.push(rec)) {
        g_packets_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

// Dedicated High-Throughput Async Writer Thread
void async_writer_thread() {
    setvbuf(stdout, nullptr, _IOFBF, 2 * 1024 * 1024);

    PacketRecord rec;

    while (g_running.load(std::memory_order_relaxed)) {
        size_t batch_count = 0;
        while (g_ring_buffer.pop(rec) && batch_count < 4096) {
            const char* proto_name = "Other";
            if (rec.proto == IPPROTO_TCP) proto_name = "TCP";
            else if (rec.proto == IPPROTO_UDP) proto_name = "UDP";
            else if (rec.proto == IPPROTO_ICMP) proto_name = "ICMP";

            std::printf("[IPFIX] src_ip=%s,dst_ip=%s,proto=%s,src_port=%u,dst_port=%u,meta=%s,bytes=%u\n",
                rec.src_ip, rec.dst_ip, proto_name, rec.src_port, rec.dst_port, rec.meta, rec.bytes);

            batch_count++;
        }

        if (batch_count > 0) {
            std::fflush(stdout);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    }
}

// Live 1-second Throughput Stats Monitor Thread
void stats_monitor_thread(pcap_t* handle) {
    uint64_t prev_captured = 0;
    auto prev_time = std::chrono::steady_clock::now();

    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - prev_time).count();
        prev_time = now;

        uint64_t curr_captured = g_packets_captured.load(std::memory_order_relaxed);
        uint64_t curr_dropped = g_packets_dropped.load(std::memory_order_relaxed);
        uint64_t pps = static_cast<uint64_t>((curr_captured - prev_captured) / std::max(0.001, elapsed));
        prev_captured = curr_captured;

        struct pcap_stat ps;
        uint64_t kern_drop = 0;
        if (handle && pcap_stats(handle, &ps) == 0) {
            kern_drop = ps.ps_drop;
        }

        std::fprintf(stderr, "[THROUGHPUT STATS] Capture Rate: %lu pps | Total Captured: %lu | Ring Drops: %lu | Kernel Drops: %lu\n",
            pps, curr_captured, curr_dropped, kern_drop);
    }
}

void start_sniffing(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev_str(device ? device : "any");

    g_running = true;
    std::thread output_thread(async_writer_thread);

    pcap_t* handle = pcap_create(dev_str.c_str(), errbuf);
    if (!handle) {
        std::fprintf(stderr, "[FlowSight] Couldn't create handle for device %s: %s, falling back to pcap_open_live\n", dev_str.c_str(), errbuf);
        handle = pcap_open_live(dev_str.c_str(), 65535, dev_str == "any" ? 0 : 1, 1, errbuf);
    } else {
        pcap_set_buffer_size(handle, 256 * 1024 * 1024);
        pcap_set_snaplen(handle, 65535);
        pcap_set_timeout(handle, 1);
        pcap_set_immediate_mode(handle, 1);

        bool try_promisc = (dev_str != "any");
        pcap_set_promisc(handle, try_promisc ? 1 : 0);

        int status = pcap_activate(handle);
        if (status < 0 && try_promisc) {
            pcap_close(handle);
            handle = pcap_create(dev_str.c_str(), errbuf);
            if (handle) {
                pcap_set_buffer_size(handle, 256 * 1024 * 1024);
                pcap_set_snaplen(handle, 65535);
                pcap_set_timeout(handle, 1);
                pcap_set_immediate_mode(handle, 1);
                pcap_set_promisc(handle, 0);
                status = pcap_activate(handle);
            }
        }

        if (status < 0) {
            std::fprintf(stderr, "[FlowSight] Couldn't activate interface %s (code %d): %s\n", dev_str.c_str(), status, pcap_geterr(handle));
            g_running = false;
            if (output_thread.joinable()) output_thread.join();
            if (handle) pcap_close(handle);
            return;
        }
    }

    if (!handle) {
        std::fprintf(stderr, "[FlowSight] Couldn't open device %s: %s\n", dev_str.c_str(), errbuf);
        g_running = false;
        if (output_thread.joinable()) output_thread.join();
        return;
    }

    std::thread stats_thread(stats_monitor_thread, handle);

    // Accept ALL raw frames on physical interface (empty filter string = 100% promiscuous capture)
    struct bpf_program fcode;
    if (pcap_compile(handle, &fcode, "", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fcode);
        pcap_freecode(&fcode);
        std::fprintf(stderr, "[FlowSight] Attached promiscuous kernel eBPF/BPF filter (accept all frames)\n");
    }

    std::fprintf(stderr, "[FlowSight] High-Speed Ring Buffer (256MB) Active on interface '%s'\n", dev_str.c_str());

    CaptureContext context{14};
    switch (pcap_datalink(handle)) {
        case DLT_LINUX_SLL: context.link_offset = 16; break;
        case DLT_LINUX_SLL2: context.link_offset = 20; break;
        case DLT_RAW: context.link_offset = 0; break;
        case DLT_NULL: context.link_offset = 4; break;
        default: break;
    }

    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&context));

    g_running = false;
    if (stats_thread.joinable()) stats_thread.join();
    if (output_thread.joinable()) output_thread.join();
    pcap_close(handle);
}