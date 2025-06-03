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

void RoutingAssignment::sendRequest(int port) {}

void RoutingAssignment::initialize() {
  // Host 객체 참조

  // 포트 개수 조회
  int port_count = getPortCount(); // HostModule::getPortCount()

  // 각 포트마다 작업 수행
  for (int port = 0; port < port_count; ++port) {
    auto ip_opt = getIPAddr(port); // HostModule::getIPAddr()
    if (!ip_opt.has_value())
      continue;

    ipv4_t ip = ip_opt.value();
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
  // Implement below

  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
