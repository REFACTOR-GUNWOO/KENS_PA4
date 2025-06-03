/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

namespace E {

static uint32_t ipToKey(const ipv4_t &ip) {
  return *reinterpret_cast<const uint32_t *>(&ip);
}

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::sendRequest(int port) {
  // RIP 헤더 설정
  rip_header_t header;
  header.command = 1; // request
  header.version = 1; // RIPv1
  header.zero_0 = 0;

  // RIP entry 설정
  rip_entry_t entry;
  entry.address_family = htons(2); // IP
  entry.zero_1 = 0;

  ipv4_t my_ip = interfaces[port];                // 자기 IP
  memcpy(&entry.ip_addr, &my_ip, sizeof(ipv4_t)); // IP 설정
  std::cout << "my_ip = " << static_cast<unsigned int>(my_ip[0]) << "."
            << static_cast<unsigned int>(my_ip[1]) << "."
            << static_cast<unsigned int>(my_ip[2]) << "."
            << static_cast<unsigned int>(my_ip[3]) << std::endl;
  entry.zero_2 = 0;
  entry.zero_3 = 0;
  entry.metric = htonl(16); // infinite

  // RIP 페이로드 크기 계산
  size_t rip_size = sizeof(header) + sizeof(entry);

  // UDP 헤더 설정
  struct udp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
  } __attribute__((packed));

  udp_header_t udp_hdr;
  udp_hdr.src_port = htons(520);
  udp_hdr.dst_port = htons(520);
  udp_hdr.len = htons(rip_size + sizeof(udp_header_t));
  udp_hdr.checksum = 0;

  // 전체 패킷 생성 (UDP 헤더 + RIP 페이로드)
  Packet packet(sizeof(udp_hdr) + rip_size);
  size_t offset = 0;
  packet.writeData(offset, &udp_hdr, sizeof(udp_hdr));
  offset += sizeof(udp_hdr);
  packet.writeData(offset, &header, sizeof(header));
  offset += sizeof(header);
  packet.writeData(offset, &entry, sizeof(entry));

  // 패킷 전송: UDP 모듈로 전송
  sendPacket("UDP", std::move(packet));
}

void debugPrintRIPPacket(const E::Packet &packet) {
  size_t totalSize = packet.getSize();
  if (totalSize < 12) {
    std::cout << "[RIP DEBUG] Too small for RIP+UDP header: " << totalSize
              << " bytes\n";
    return;
  }

  // 1. UDP Header (8 bytes)
  struct udp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
  } __attribute__((packed));

  udp_header_t udp;
  packet.readData(0, &udp, sizeof(udp));
  std::cout << "[UDP Header]\n";
  std::cout << "  src_port: " << ntohs(udp.src_port)
            << ", dst_port: " << ntohs(udp.dst_port)
            << ", len: " << ntohs(udp.len) << ", checksum: 0x" << std::hex
            << ntohs(udp.checksum) << std::dec << "\n";

  // 2. RIP Header (4 bytes)
  if (totalSize < 12)
    return;
  E::rip_header_t rip_header;
  packet.readData(8, &rip_header, sizeof(rip_header));
  std::cout << "[RIP Header]\n";
  std::cout << "  command: " << static_cast<int>(rip_header.command)
            << ", version: " << static_cast<int>(rip_header.version)
            << ", zero: " << rip_header.zero_0 << "\n";

  // 3. RIP entries (20 bytes each)
  size_t offset = 12;
  int index = 0;
  while (offset + sizeof(E::rip_entry_t) <= totalSize) {
    E::rip_entry_t entry;
    packet.readData(offset, &entry, sizeof(entry));
    offset += sizeof(entry);

    E::ipv4_t ip;
    memcpy(&ip, &entry.ip_addr, sizeof(ip));

    std::cout << "[RIP Entry " << index++ << "] "
              << "IP = " << static_cast<int>(ip[0]) << "."
              << static_cast<int>(ip[1]) << "." << static_cast<int>(ip[2])
              << "." << static_cast<int>(ip[3])
              << ", metric = " << ntohl(entry.metric) << "\n";
  }
}

void RoutingAssignment::sendResponseBroadcast(int port) {
  // RIP 응답 헤더
  rip_header_t header;
  header.command = 2; // response
  header.version = 1;
  header.zero_0 = 0;

  // RIP entry 목록 만들기
  std::vector<rip_entry_t> entries;

  for (const auto &[key, entry] : table) {
    rip_entry_t rip_entry;
    memcpy(&rip_entry.ip_addr, &entry.destination, sizeof(uint32_t));

    rip_entry.address_family = htons(2);
    rip_entry.zero_1 = 0;
    rip_entry.zero_2 = 0;
    rip_entry.zero_3 = 0;
    rip_entry.metric = htonl(entry.cost > 15 ? 16 : entry.cost); // 최대 16
    entries.push_back(rip_entry);
  }

  // 총 길이 계산
  size_t rip_size = sizeof(rip_header_t) + entries.size() * sizeof(rip_entry_t);
  size_t udp_size = rip_size + 8;

  // UDP 헤더 작성
  struct udp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
  } __attribute__((packed));

  udp_header_t udp_hdr;
  udp_hdr.src_port = htons(520);
  udp_hdr.dst_port = htons(520);
  udp_hdr.len = htons(udp_size);
  udp_hdr.checksum = 0;

  // 전체 패킷 생성
  Packet packet(sizeof(udp_hdr) + rip_size);
  size_t offset = 0;
  packet.writeData(offset, &udp_hdr, sizeof(udp_hdr));
  offset += sizeof(udp_hdr);
  packet.writeData(offset, &header, sizeof(header));
  offset += sizeof(header);
  for (const auto &e : entries) {
    packet.writeData(offset, &e, sizeof(e));
    offset += sizeof(e);
  }

  // 브로드캐스트 IP 설정
  ipv4_t dest;
  std::memset(&dest, 0xFF, sizeof(dest));

  // 전송
  sendPacket("UDP", std::move(packet));
}

void RoutingAssignment::initialize() {
  // Host 객체 참조

  // 포트 개수 조회
  int port_count = getPortCount(); // HostModule::getPortCount()

  // 각 포트마다 작업 수행
  for (int port = 0; port < port_count; ++port) {
    auto ip_opt = getIPAddr(port); // HostModule::getIPAddr()
    if (!ip_opt.has_value()) {
      std::cout << "ip_opt: 없음" << std::endl;
      continue;
    }

    ipv4_t ip = ip_opt.value();
    std::cout << "ip_opt: " << static_cast<unsigned int>(ip[0]) << "."
              << static_cast<unsigned int>(ip[1]) << "."
              << static_cast<unsigned int>(ip[2]) << "."
              << static_cast<unsigned int>(ip[3]) << std::endl;
    interfaces[port] = ip; // 포트-IP 매핑 저장

    // 자기 자신에 대한 라우팅 정보 추가
    RouteEntry entry{.destination = ip,
                     .prefix_len = 32,
                     .cost = 0, // 본인은 거리 0
                     .port = port,
                     .last_updated = getCurrentTime()};
    table[ipToKey(ip)] = entry;

    // 각 포트로 RIP Request 전송
    sendRequest(port);
  }
  std::cout << "interfaces size = " << interfaces.size() << std::endl;

  // 타이머 등록 (5초 주기 브로드캐스트)
  addTimer("broadcast", 5000000);
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  uint32_t key = ipToKey(ipv4);
  auto it = table.find(key);
  for (const auto &[k, e] : table) {
    std::cout << "Entry: " << static_cast<int>(e.destination[0]) << "."
              << static_cast<int>(e.destination[1]) << "."
              << static_cast<int>(e.destination[2]) << "."
              << static_cast<int>(e.destination[3]) << " cost = " << e.cost
              << std::endl;
  }

  if (it != table.end()) {
    return it->second.cost;
  }
  return static_cast<Size>(-1); // 없으면 -1
}

int RoutingAssignment::getPortByModuleName(const std::string &name) {
  for (const auto &[port, ip] : interfaces) {
    if ("port" + std::to_string(port) == name)
      return port;
  }
  return -1; // 오류 처리 필요 시
}

int getPortBySenderIP(const ipv4_t &sender_ip) {
  for (const auto &[port, ip] : interfaces) {
    if (ip != sender_ip) {
      return port;
    }
  }
  return -1;
}

ipv4_t guessSenderIPFromEntries(const std::vector<rip_entry_t> &entries) {
  for (const auto &entry : entries) {
    if (ntohl(entry.metric) == 0) {
      ipv4_t ip;
      std::memcpy(&ip, &entry.ip_addr, sizeof(ipv4_t));
      return ip;
    }
  }

  // fallback: 첫 엔트리 IP (없으면 0.0.0.0)
  if (!entries.empty()) {
    ipv4_t ip;
    std::memcpy(&ip, &entries[0].ip_addr, sizeof(ipv4_t));
    return ip;
  }

  return {0, 0, 0, 0};
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  std::cout << "패킷 도착 from " << fromModule
            << ", size = " << packet.getSize() << std::endl;

  if (packet.getSize() < sizeof(rip_header_t))
    return;

  rip_header_t header;
  packet.readData(8, &header, sizeof(header));

  size_t offset = sizeof(header) + 8;
  std::cout << "offset = " << offset << std::endl;
  size_t entry_count = (packet.getSize() - offset) / sizeof(rip_entry_t);
  std::cout << "entry_count = " << entry_count << std::endl;
  if ((packet.getSize() - offset) % sizeof(rip_entry_t) != 0)
    return;

  std::vector<rip_entry_t> entries(entry_count);
  for (size_t i = 0; i < entry_count; ++i) {
    packet.readData(offset, &entries[i], sizeof(rip_entry_t));
    offset += sizeof(rip_entry_t);
  }

  ipv4_t sender_ip = guessSenderIPFromEntries(entries);
  std::cout << "sender_ip = " << static_cast<unsigned int>(sender_ip[0]) << "."
            << static_cast<unsigned int>(sender_ip[1]) << "."
            << static_cast<unsigned int>(sender_ip[2]) << "."
            << static_cast<unsigned int>(sender_ip[3]) << std::endl;

  std::cout << "interfaces size = " << interfaces.size() << std::endl;
  int port = getPortBySenderIP(sender_ip);
  std::cout << "port = " << port << std::endl;
  std::cout << "[packetArrived] header.command = "
            << static_cast<int>(header.command)
            << ", size = " << packet.getSize() << std::endl;

  if (header.command == 1) {
    sendResponseBroadcast(port);
  } else if (header.command == 2) {
    // 실제 발신자 IP는 아직 모름 -> 예시로 0.0.0.0 전달
    ipv4_t dummy_ip{};
    updateRoutingTable(port, dummy_ip, entries);
  }
}

void RoutingAssignment::updateRoutingTable(
    int port, ipv4_t sender_ip, const std::vector<rip_entry_t> &entries) {
  // std::cout << "updateRoutingTable called on port " << port << std::endl;

  Size cost_to_sender = linkCost(port);

  for (const auto &e : entries) {
    ipv4_t dst;
    memcpy(&dst, &e.ip_addr, sizeof(ipv4_t));

    if (dst == interfaces[port])
      continue; // 자기 자신 무시

    Size metric = ntohl(e.metric);
    metric = std::min(Size(16), metric + cost_to_sender);

    uint32_t key = ipToKey(dst);
    auto it = table.find(key);

    if (metric >= 16) {
      // infinite metric이면 제거
      if (it != table.end() && it->second.port == port) {
        table.erase(it);
      }
      continue;
    }

    Time now = getCurrentTime();

    if (it == table.end()) {
      // 새로운 경로 추가
      RouteEntry entry{dst, 32, metric, port, now};
      table[key] = entry;
    } else {
      auto &existing = it->second;
      if (existing.port == port || metric < existing.cost) {
        existing.cost = metric;
        existing.port = port;
        existing.last_updated = now;
      }
    }
  }
}

void RoutingAssignment::timerCallback(std::any payload) {
  Time now = getCurrentTime();

  // 180초(=180000000 usec) 이상된 entry 삭제
  for (auto it = table.begin(); it != table.end();) {
    if (now - it->second.last_updated > 180000000) {
      it = table.erase(it);
    } else {
      ++it;
    }
  }

  // 5초마다 모든 포트로 응답 브로드캐스트
  for (const auto &[port, ip] : interfaces) {
    sendResponseBroadcast(port);
  }

  // 다시 타이머 등록 (5초 후)
  addTimer("broadcast", 5000000);
}

} // namespace E
