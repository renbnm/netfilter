#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <string>
#include <algorithm>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/types.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

static std::string blocked_host;
static volatile sig_atomic_t stop = 0;

static void signal_handler(int) {
    stop = 1;
}

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() &&
           (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
        start++;
    }

    size_t end = s.size();
    while (end > start &&
           (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }

    return s.substr(start, end - start);
}

static std::string lower_string(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string remove_port_if_exists(const std::string& host) {
    // IPv6 literal 형태는 이번 과제 범위에서 제외
    if (!host.empty() && host[0] == '[') return host;

    size_t colon = host.find(':');
    if (colon == std::string::npos) return host;

    return host.substr(0, colon);
}

static bool extract_host(const unsigned char* data, int len, std::string& host) {
    std::string http(reinterpret_cast<const char*>(data), len);

    size_t pos = 0;

    while (pos < http.size()) {
        size_t end = http.find('\n', pos);
        std::string line;

        if (end == std::string::npos) {
            line = http.substr(pos);
            pos = http.size();
        } else {
            line = http.substr(pos, end - pos);
            pos = end + 1;
        }

        line = trim(line);

        if (line.empty()) break;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = lower_string(trim(line.substr(0, colon)));
        std::string value = trim(line.substr(colon + 1));

        if (key == "host") {
            host = value;
            return true;
        }
    }

    return false;
}

static bool is_http_request_payload(const unsigned char* data, int len) {
    if (len <= 0) return false;

    std::string payload(reinterpret_cast<const char*>(data), len);

    const char* methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };

    for (const char* method : methods) {
        size_t mlen = std::strlen(method);
        if (payload.size() >= mlen && payload.compare(0, mlen, method) == 0) {
            return true;
        }
    }

    return false;
}

static bool is_blocked_host(const std::string& host) {
    std::string h = lower_string(trim(host));
    std::string target = lower_string(trim(blocked_host));

    if (h == target) return true;

    std::string h_without_port = remove_port_if_exists(h);
    if (h_without_port == target) return true;

    return false;
}

static bool should_drop_packet(unsigned char* packet, int packet_len) {
    if (packet_len < static_cast<int>(sizeof(struct ip))) return false;

    struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);

    if (ip_hdr->ip_v != 4) return false;
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    if (ip_hdr_len < 20) return false;
    if (packet_len < ip_hdr_len + static_cast<int>(sizeof(struct tcphdr))) return false;

    struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(packet + ip_hdr_len);

    int tcp_hdr_len = tcp_hdr->th_off * 4;
    if (tcp_hdr_len < 20) return false;
    if (packet_len < ip_hdr_len + tcp_hdr_len) return false;

    unsigned char* tcp_payload = packet + ip_hdr_len + tcp_hdr_len;
    int tcp_payload_len = packet_len - ip_hdr_len - tcp_hdr_len;

    if (!is_http_request_payload(tcp_payload, tcp_payload_len)) return false;

    std::string host;
    if (!extract_host(tcp_payload, tcp_payload_len, host)) return false;

    if (is_blocked_host(host)) {
        printf("[DROP] Host: %s\n", host.c_str());
        return true;
    }

    printf("[ACCEPT] Host: %s\n", host.c_str());
    return false;
}

static uint32_t get_packet_id(struct nfq_data* nfa) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);

    if (ph == nullptr) return 0;

    return ntohl(ph->packet_id);
}

static int callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {
    (void)nfmsg;
    (void)data;

    uint32_t id = get_packet_id(nfa);

    unsigned char* packet = nullptr;
    int packet_len = nfq_get_payload(nfa, &packet);

    uint32_t verdict = NF_ACCEPT;

    if (packet_len >= 0 && packet != nullptr) {
        if (should_drop_packet(packet, packet_len)) {
            verdict = NF_DROP;
        }
    }

    return nfq_set_verdict(qh, id, verdict, 0, nullptr);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "syntax : %s <host>\n", argv[0]);
        fprintf(stderr, "sample : %s test.gilgil.net\n", argv[0]);
        return 1;
    }

    blocked_host = argv[1];

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct nfq_handle* h = nfq_open();
    if (h == nullptr) {
        fprintf(stderr, "nfq_open failed\n");
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_unbind_pf failed\n");
        nfq_close(h);
        return 1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_bind_pf failed\n");
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &callback, nullptr);
    if (qh == nullptr) {
        fprintf(stderr, "nfq_create_queue failed\n");
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);

    char buf[4096] __attribute__((aligned));

    while (!stop) {
        int rv = recv(fd, buf, sizeof(buf), 0);

        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (errno == EINTR) continue;

        if (errno == ENOBUFS) {
            printf("losing packets\n");
            continue;
        }

        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
