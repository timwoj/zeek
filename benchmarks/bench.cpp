// See the file "COPYING" in the main distribution directory for copyright.

// Zeek performance benchmarks using google_benchmark.
// These benchmarks measure performance of common operations
// representative of Zeek's core processing paths.

#include <arpa/inet.h>
#include <benchmark/benchmark.h>
#include <cstring>
#include <string>
#include <vector>

// Benchmark: IPv4 address parsing via inet_pton, mirroring
// the IPAddr::Init() code path in Zeek.
static void BM_ParseIPv4(benchmark::State& state) {
    const char* addr = "192.168.1.1";
    in6_addr result;
    for ( auto _ : state ) {
        memset(&result, 0, sizeof(result));
        // v4-mapped prefix
        result.s6_addr[10] = 0xff;
        result.s6_addr[11] = 0xff;
        inet_pton(AF_INET, addr, &result.s6_addr[12]);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ParseIPv4);

// Benchmark: IPv6 address parsing via inet_pton.
static void BM_ParseIPv6(benchmark::State& state) {
    const char* addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    in6_addr result;
    for ( auto _ : state ) {
        inet_pton(AF_INET6, addr, &result);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ParseIPv6);

// Benchmark: IPv4 address to string conversion.
static void BM_IPv4ToString(benchmark::State& state) {
    in_addr addr;
    inet_pton(AF_INET, "10.0.0.1", &addr);
    char buf[INET_ADDRSTRLEN];
    for ( auto _ : state ) {
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        benchmark::DoNotOptimize(buf);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_IPv4ToString);

// Benchmark: IPv6 address to string conversion.
static void BM_IPv6ToString(benchmark::State& state) {
    in6_addr addr;
    inet_pton(AF_INET6, "2001:db8:85a3::8a2e:370:7334", &addr);
    char buf[INET6_ADDRSTRLEN];
    for ( auto _ : state ) {
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        benchmark::DoNotOptimize(buf);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_IPv6ToString);

// Benchmark: memcmp-based IP address comparison, mirroring
// the IPAddr operator== implementation.
static void BM_IPAddrCompare(benchmark::State& state) {
    in6_addr a, b;
    inet_pton(AF_INET6, "2001:db8::1", &a);
    inet_pton(AF_INET6, "2001:db8::2", &b);
    for ( auto _ : state ) {
        int result = memcmp(&a, &b, sizeof(in6_addr));
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_IPAddrCompare);

// Benchmark: String copy and concatenation, representative of
// Zeek's frequent string operations in protocol analysis.
static void BM_StringConcat(benchmark::State& state) {
    std::string a = "GET /index.html HTTP/1.1";
    std::string b = "Host: www.example.com";
    for ( auto _ : state ) {
        std::string result = a + "\r\n" + b + "\r\n\r\n";
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_StringConcat);

// Benchmark: String find/search operations, representative of
// pattern matching in protocol parsers.
static void BM_StringFind(benchmark::State& state) {
    std::string haystack =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 1234\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    std::string needle = "Content-Length";
    for ( auto _ : state ) {
        auto pos = haystack.find(needle);
        benchmark::DoNotOptimize(pos);
    }
}
BENCHMARK(BM_StringFind);

// Benchmark: Hex encoding of bytes, representative of
// the kind of rendering Zeek does for binary data.
static void BM_HexEncode(benchmark::State& state) {
    static const char hex[] = "0123456789abcdef";
    const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    for ( auto _ : state ) {
        std::string result;
        result.reserve(sizeof(data) * 2);
        for ( auto b : data ) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0x0f]);
        }
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_HexEncode);

// Benchmark: Simple base64 encoding, representative of
// Zeek's Base64Converter operations.
static void BM_Base64Encode(benchmark::State& state) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::string input = "Hello, Zeek Network Security Monitor!";
    for ( auto _ : state ) {
        std::string result;
        result.reserve(((input.size() + 2) / 3) * 4);
        unsigned int val = 0;
        int valb = -6;
        for ( unsigned char c : input ) {
            val = (val << 8) + c;
            valb += 8;
            while ( valb >= 0 ) {
                result.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if ( valb > -6 )
            result.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while ( result.size() % 4 )
            result.push_back('=');
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_Base64Encode);

// Benchmark: Vector push_back with reserve, representative of
// Zeek's frequent use of vectors for connection tracking.
static void BM_VectorPushBack(benchmark::State& state) {
    for ( auto _ : state ) {
        std::vector<uint64_t> v;
        v.reserve(1024);
        for ( int i = 0; i < 1024; ++i )
            v.push_back(static_cast<uint64_t>(i));
        benchmark::DoNotOptimize(v);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_VectorPushBack);

BENCHMARK_MAIN();
