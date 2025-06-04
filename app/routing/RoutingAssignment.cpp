/*
 * E_RoutingAssignment.cpp
 *
 */

#include "RoutingAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/udp.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {
  ipv4_t broadCastIp = {255, 255, 255, 255};

  for (int i = 0; i < getPortCount(); i++) {
    ipv4_t source_ip = getIPAddr(i).value();

    struct rip_entry_t entry_t = {
        .address_family = htons(2),
        .zero_1 = 0,
        .ip_addr = static_cast<uint32_t>(NetworkUtil::arrayToUINT64(source_ip)),
        .zero_2 = 0,
        .zero_3 = 0,
        .metric = 0};

    this->distance_vector_table.push_back(entry_t);
    this->my_ips.push_back(source_ip);

    struct rip_entry_t rip_entry_t = {.address_family = htons(0),
                                      .zero_1 = 0,
                                      .ip_addr = 0,
                                      .zero_2 = 0,
                                      .zero_3 = 0,
                                      .metric = htonl(301)};

    size_t packet_size = sizeof(udphdr) + sizeof(rip_header_t);
    size_t udp_header_start_offset = 34;
    Packet packet(udp_header_start_offset + packet_size);

    // broadcast a request
    packet.writeData(26, &source_ip, 4);   // source ipaddress
    packet.writeData(30, &broadCastIp, 4); // destination ipaddress

    struct udphdr udphdr = {.uh_sport = htons(520),
                            .uh_dport = htons(520),
                            .uh_sum = 0,
                            .uh_ulen = htons(32)};

    struct rip_header_t rip_header = {.command = 1, .version = 1, .zero_0 = 0};

    udphdr.uh_sum = 0;
    packet.writeData(34, &udphdr, sizeof(udphdr));
    packet.writeData(38, &rip_header, sizeof(rip_header_t));

    this->sendPacket("IPv4", std::move(packet));
  }

  this->addTimer("", TimeUtil::makeTime(30, TimeUtil::SEC));
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {

  for (int i = 0; i < this->distance_vector_table.size(); i++) {
    if (this->distance_vector_table[i].ip_addr ==
        (uint32_t)NetworkUtil::arrayToUINT64(ipv4))
      return ntohl(this->distance_vector_table[i].metric);
  }

  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  ipv4_t dest_ip;
  packet.readData(26, &dest_ip, 4);

  int port = getRoutingTable(dest_ip);
  ipv4_t source_ip = getIPAddr(port).value();

  struct udphdr udphdr;
  packet.readData(34, &udphdr, sizeof(udphdr));

  size_t length = ntohs(udphdr.uh_ulen);
  int entry_count =
      (length - sizeof(udphdr) - sizeof(rip_header_t)) / sizeof(rip_entry_t);

  struct rip_t *rip_t = (struct rip_t *)malloc(
      sizeof(struct rip_t) + sizeof(rip_entry_t) * entry_count);
  packet.readData(34 + sizeof(udphdr), rip_t, length - 8);

  if (rip_t->header.command == 1) { // got request
    size_t packet_size = sizeof(udphdr) + sizeof(rip_t);
    Packet packetToSend(packet_size + 34);

    packetToSend.writeData(26, &source_ip, 4);
    packetToSend.writeData(30, &dest_ip, 4);

    udphdr.uh_ulen = htons(packet_size);
    udphdr.uh_sum = 0;

    struct rip_t *send_rip_t = (struct rip_t *)malloc(
        sizeof(struct rip_t) +
        sizeof(rip_entry_t) * this->distance_vector_table.size());

    send_rip_t->header.command = 2;
    send_rip_t->header.version = 1;
    send_rip_t->header.zero_0 = 0;

    for (int i = 0; i < this->distance_vector_table.size(); i++) {
      send_rip_t->entries[i] = this->distance_vector_table[i];
    }

    udphdr.uh_sum = 0;
    packetToSend.writeData(34, &udphdr, sizeof(udphdr));
    packetToSend.writeData(38, send_rip_t, packet_size - sizeof(udphdr));

    this->sendPacket("IPv4", std::move(packetToSend));

    free(send_rip_t);

  } else if (rip_t->header.command == 2) { // got response
    int changed = 0;                       //  any update exists?
    for (int i = 0; i < entry_count; i++) {
      struct rip_entry_t rip_entry_t; //  새로 들어갈 애
      rip_entry_t.address_family = rip_t->entries[i].address_family;
      rip_entry_t.ip_addr = rip_t->entries[i].ip_addr;
      rip_entry_t.zero_1 = 0;
      rip_entry_t.zero_2 = 0;
      rip_entry_t.zero_3 = 0;

      ipv4_t temp;
      for (int j = 0; j < 4; j++) {
        temp[j] = ((rip_entry_t.ip_addr >> j * 8) & 0xFF);
      }

      if (rip_t->entries[i].metric >= htonl(16)) { // unreachable
        rip_entry_t.metric = htonl(16);
      } else {
        int port_num = getRoutingTable(dest_ip);
        rip_entry_t.metric =
            htonl(ntohl(rip_t->entries[i].metric) + linkCost(port_num));
      }

      if (find(this->my_ips.begin(), this->my_ips.end(), temp) !=
          this->my_ips.end()) { //  Is that my IP address?
        continue;
      }

      int found = 0;

      for (int j = 0; j < this->distance_vector_table.size(); j++) {
        if (this->distance_vector_table[j].ip_addr == rip_entry_t.ip_addr) {
          found = 1;
          uint32_t old = this->distance_vector_table[j].metric;
          this->distance_vector_table[j].metric =
              htonl(MIN(ntohl(this->distance_vector_table[j].metric),
                        ntohl(rip_entry_t.metric)));
          if (old != this->distance_vector_table[j].metric) { // changed
            changed = 1;
          }
        }
      }
      if (found == 0) {
        changed = 1;
        this->distance_vector_table.push_back(rip_entry_t);
      }
    }
    if (changed == 1) { // notify change(s) to neighbors
      for (int i = 0; i < getPortCount(); i++) {
        size_t packet_size = 8 + 4 + 20 * this->distance_vector_table.size();
        Packet pkt(packet_size + 34); // udp header 8bytes + rip_header 4bytes +
                                      // rip_entries 20bytes each

        ipv4_t dest_ip;
        for (int j = 0; j < 4; j++) {
          dest_ip[j] = (uint8_t)255;
        }
        std::optional<ipv4_t> ip = getIPAddr(i);
        ipv4_t source_ip_send = ip.value();

        if (source_ip == source_ip_send) {
          continue;
        }

        size_t ip_start = 14;
        pkt.writeData(ip_start + 12, &source_ip_send, 4); // source ipaddress
        pkt.writeData(ip_start + 16, &dest_ip, 4); // destination ipaddress

        struct udphdr udphdr;
        udphdr.uh_sport = htons(520);
        udphdr.uh_dport = htons(520);
        udphdr.uh_ulen = htons(packet_size);
        udphdr.uh_sum = 0;

        struct rip_t *send_rip_t = (struct rip_t *)malloc(
            sizeof(struct rip_t) + 20 * this->distance_vector_table.size());
        send_rip_t->header.command = (uint8_t)2;
        send_rip_t->header.version = (uint8_t)1;
        send_rip_t->header.zero_0 = 0;

        for (int i = 0; i < this->distance_vector_table.size(); i++) {
          send_rip_t->entries[i] = this->distance_vector_table[i];
        }

        void *udp_packet = malloc(packet_size);
        memcpy(udp_packet, &udphdr, 8);
        memcpy((uint8_t *)udp_packet + 8, send_rip_t, packet_size - 8);

        udphdr.uh_sum = 0;
        memcpy(udp_packet, &udphdr, 8);

        pkt.writeData(34, udp_packet, packet_size);

        free(udp_packet);

        this->sendPacket("IPv4", std::move(pkt));
        free(send_rip_t);
      }
    }
  }
  free(rip_t);
}

void RoutingAssignment::timerCallback(std::any payload) {
  // broadcast response
  for (int i = 0; i < getPortCount(); i++) {
    size_t packet_size = 8 + 4 + 20 * this->distance_vector_table.size();
    Packet pkt(
        packet_size +
        34); // udp header 8bytes + rip_header 4bytes + rip_entries 20bytes each

    ipv4_t dest_ip;
    for (int j = 0; j < 4; j++) {
      dest_ip[j] = (uint8_t)255;
    }
    int port = getRoutingTable(dest_ip);
    std::optional<ipv4_t> ip = getIPAddr(port);
    ipv4_t source_ip = ip.value();

    size_t ip_start = 14;
    pkt.writeData(ip_start + 12, &source_ip, 4); // source ipaddress
    pkt.writeData(ip_start + 16, &dest_ip, 4);   // destination ipaddress

    struct udphdr udphdr;
    udphdr.uh_sport = htons(520);
    udphdr.uh_dport = htons(520);
    udphdr.uh_ulen = htons(packet_size);
    udphdr.uh_sum = 0;

    struct rip_t *rip_t = (struct rip_t *)malloc(
        sizeof(struct rip_t) + 20 * this->distance_vector_table.size());
    rip_t->header.command = (uint8_t)2;
    rip_t->header.version = (uint8_t)1;
    rip_t->header.zero_0 = 0;

    for (int i = 0; i < this->distance_vector_table.size(); i++) {
      rip_t->entries[i] = this->distance_vector_table[i];
    }

    void *udp_packet = malloc(packet_size);
    memcpy(udp_packet, &udphdr, 8);
    memcpy((uint8_t *)udp_packet + 8, rip_t, packet_size - 8);

    uint16_t checksum =
        NetworkUtil::tcp_sum((uint32_t)NetworkUtil::arrayToUINT64(source_ip),
                             (uint32_t)NetworkUtil::arrayToUINT64(dest_ip),
                             (uint8_t *)udp_packet, packet_size);
    checksum = ~checksum;
    checksum = htons(checksum);
    udphdr.uh_sum = checksum;
    memcpy(udp_packet, &udphdr, 8);

    pkt.writeData(34, udp_packet, packet_size);

    free(udp_packet);

    this->sendPacket("IPv4", std::move(pkt));
    free(rip_t);
  }
}

} // namespace E