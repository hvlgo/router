/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  if (packet.size() < sizeof(ethernet_hdr)) {
    std::cerr << "Received packet, but the header is truncated, ignoring" << std::endl;
    return;
  }

  ethernet_hdr* e_hdr;
  e_hdr = (ethernet_hdr*) packet.data();

  if (!isRightMac(e_hdr->ether_dhost, iface)) {
    std::cerr << "Received packet, but MAC address is not broadcast address or \
    address of corresponding interface, ignoring" << std::endl;
    return;
  }
  Buffer payload(packet.data() + sizeof(ethernet_hdr), packet.data() + packet.size());
  if (ntohs(e_hdr->ether_type) == ethertype_arp) {
    SimpleRouter::handleArpPacket(payload, iface, e_hdr->ether_shost);
  }
  else if (ntohs(e_hdr->ether_type) == ethertype_ip) {
    SimpleRouter::handleIpPacket(payload, iface, e_hdr->ether_shost, e_hdr->ether_dhost);
  }
  else {
    std::cerr << "Received packet, but type is not arp or ipv4, ignoring" << std::endl;
    return;
  }
}

bool isRightMac(const uint8_t * mac, const Interface * iface)
{
  uint8_t broadcast_mac[ETHER_ADDR_LEN];
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    broadcast_mac[i] = 0xffU;
  }
  if (memcmp(broadcast_mac, mac, ETHER_ADDR_LEN) == 0)
    return true;
  return memcmp(iface->addr.data(), mac, ETHER_ADDR_LEN) == 0;
}

void SimpleRouter::handleArpPacket(const Buffer& arp_packet, const Interface * iface, uint8_t * s_mac)
{
  if (arp_packet.size() < sizeof(arp_hdr)) {
    std::cerr << "Received arp packet, but the header is truncated, ignoring" << std::endl;
    return;
  }
  arp_hdr* arp_h;
  arp_h = (arp_hdr *) arp_packet.data();

  if (ntohs(arp_h->arp_hrd) != arp_hrd_ethernet) {
    std::cerr << "Received arp packet, but format of hardware address is not ethernet, ignoring" << std::endl;
    return;
  }

  uint16_t opcode = arp_h->arp_op;
  if (ntohs(opcode) == arp_op_request) {
    if (arp_h->arp_tip != iface->ip) {
      std::cerr << "Received arp packet, but dst ip incorrect, ignoring" << std::endl;
      return;
    }

    uint8_t out_buf[sizeof(ethernet_hdr) + sizeof(arp_hdr)];
    ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
    out_e_hdr->ether_type = htons(ethertype_arp);
    memcpy(out_e_hdr->ether_dhost, s_mac, ETHER_ADDR_LEN);
    memcpy(out_e_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

    arp_hdr * out_arp_h = (arp_hdr *) (out_buf + sizeof(ethernet_hdr));
    memcpy(out_arp_h, arp_h, sizeof(arp_hdr));
    out_arp_h->arp_op = htons(arp_op_reply);
    memcpy(out_arp_h->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
    out_arp_h->arp_sip = iface->ip;
    memcpy(out_arp_h->arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN);
    out_arp_h->arp_tip = arp_h->arp_sip;

    const Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
    SimpleRouter::sendPacket(out_packet, iface->name);
    return;
  }
  else if (ntohs(opcode) == arp_op_reply) {
    uint32_t arp_s_ip = arp_h->arp_sip;
    uint8_t * arp_s_mac = arp_h->arp_sha;
    Buffer arp_s_mac_buf(arp_s_mac, arp_s_mac + ETHER_ADDR_LEN);
    std::shared_ptr<ArpRequest> arp_request = m_arp.insertArpEntry(arp_s_mac_buf, arp_s_ip);
    for (PendingPacket pending_packet : arp_request->packets) {
      ethernet_hdr * out_e_hdr = (ethernet_hdr *) pending_packet.packet.data();
      memcpy(out_e_hdr->ether_dhost, arp_s_mac, ETHER_ADDR_LEN);
      SimpleRouter::sendPacket(pending_packet.packet, pending_packet.iface);
    }
    m_arp.removeRequest(arp_request);
    return;
  }
  else {
    std::cerr << "Received arp packet, but opcode is unknown, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::handleIpPacket(const Buffer& ip_packet, const Interface * iface, uint8_t * s_mac, uint8_t * d_mac) {
  if (ip_packet.size() < sizeof(ip_hdr)) {
    std::cerr << "Received ip packet, but the header is truncated, ignoring" << std::endl;
    return;
  }

  ip_hdr * ip_h = (ip_hdr *) ip_packet.data();
  uint16_t origin_ip_cksum = ip_h->ip_sum;
  ip_h->ip_sum = 0x0;
  if (cksum(ip_h, sizeof(ip_hdr)) != origin_ip_cksum) {
    std::cerr << "Received ip packet, but the checksum is wrong, ignoring" << std::endl;
    return;
  }
  ip_h->ip_sum = origin_ip_cksum;
  if (ip_h->ip_ttl <= 1) {
    sendICMPt3Packet(ip_h, 11, 0, iface, s_mac, d_mac);
    return;
  }

  if (findIfaceByIp(ip_h->ip_dst) != nullptr) {
    if (ip_h->ip_p == ip_protocol_tcp || ip_h->ip_p == ip_protocol_udp) {
      sendICMPt3Packet(ip_h, 3, 3, iface, s_mac, d_mac);
      return;
    }
    else if (ip_h->ip_p == ip_protocol_icmp) {
      if (((icmp_hdr *) (ip_packet.data() + sizeof(ip_hdr)))->icmp_type == 0x08) {
        icmp_hdr * icmp_h = (icmp_hdr *) (ip_packet.data() + sizeof(ip_hdr));
        uint16_t origin_icmp_cksum = icmp_h->icmp_sum;
        icmp_h->icmp_sum = 0x0;
        if (cksum(ip_packet.data() + sizeof(ip_hdr), ip_packet.size() - sizeof(ip_hdr)) != origin_icmp_cksum) {
          std::cerr << "Received icmp echo request packet, but the checksum is wrong, ignoring" << std::endl;
          return;
        }
        icmp_h->icmp_sum = origin_icmp_cksum;
        uint8_t out_buf[sizeof(ethernet_hdr) + ip_packet.size()];
        ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
        memcpy(out_e_hdr->ether_dhost, s_mac, ETHER_ADDR_LEN);
        memcpy(out_e_hdr->ether_shost, d_mac, ETHER_ADDR_LEN);
        out_e_hdr->ether_type = htons(ethertype_ip);
        memcpy(out_buf + sizeof(ethernet_hdr), ip_packet.data(), ip_packet.size());
        ip_hdr * out_ip_h = (ip_hdr *) (out_buf + sizeof(ethernet_hdr));
        out_ip_h->ip_ttl = 64;
        out_ip_h->ip_dst = ip_h->ip_src;
        out_ip_h->ip_src = ip_h->ip_dst;
        out_ip_h->ip_sum = 0x0;
        out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr));
        icmp_hdr * out_icmp_h = (icmp_hdr *) (out_buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        out_icmp_h->icmp_type = 0x00;
        out_icmp_h->icmp_code = 0x00;
        out_icmp_h->icmp_sum = 0x00;
        out_icmp_h->icmp_sum = cksum(out_buf + sizeof(ethernet_hdr) + sizeof(ip_hdr), ip_packet.size() - sizeof(ip_hdr));
        Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
        sendPacket(out_packet, iface->name);
        return;
      }
      else {
        std::cerr << "Received icmp packet, but the type is unknown, ignoring" << std::endl;
        return;
      }
    }
  }
  
  RoutingTableEntry result_route_entry;
  try {
    result_route_entry = m_routingTable.lookup(ip_h->ip_dst);
  } catch(...) {
    std::cerr << "Received ip packet, but not route entry for it, ignoring" << std::endl;
    return;
  }
  const Interface * result_iface = findIfaceByName(result_route_entry.ifName);
  if (result_iface == nullptr) {
    std::cerr << "Received ip packet, but the corresponding interface is unknown, ignoring" << std::endl;
    return;
  }

  uint8_t out_buf[sizeof(ethernet_hdr) + ip_packet.size()];
  ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
  memcpy(out_e_hdr->ether_shost, result_iface->addr.data(), ETHER_ADDR_LEN);
  out_e_hdr->ether_type = htons(ethertype_ip);
  memcpy(out_buf + sizeof(ethernet_hdr), ip_packet.data(), ip_packet.size());
  ip_hdr * out_ip_h = (ip_hdr *) (out_buf + sizeof(ethernet_hdr));
  out_ip_h->ip_ttl--;
  out_ip_h->ip_sum = 0x0;
  out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr));

  std::shared_ptr<ArpEntry> result_arp_entry = m_arp.lookup(out_ip_h->ip_dst);
  if (result_arp_entry == nullptr) {
    m_arp.queueRequest(out_ip_h->ip_dst, Buffer(out_buf, out_buf + sizeof(out_buf)), result_iface->name);
    return;
  }
  memcpy(out_e_hdr->ether_dhost, result_arp_entry->mac.data(), ETHER_ADDR_LEN);
  Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
  sendPacket(out_packet, result_iface->name);
  return;
}

void SimpleRouter::sendICMPt3Packet(ip_hdr * ip_h, uint8_t out_icmp_type, uint8_t out_icmp_code, const Interface * iface, uint8_t * s_mac, uint8_t * d_mac) {
  uint8_t out_buf[sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr)];
  ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
  memcpy(out_e_hdr->ether_dhost, s_mac, ETHER_ADDR_LEN);
  memcpy(out_e_hdr->ether_shost, d_mac, ETHER_ADDR_LEN);
  out_e_hdr->ether_type = htons(ethertype_ip);

  memcpy(out_buf + sizeof(ethernet_hdr), ip_h, sizeof(ip_hdr));
  ip_hdr * out_ip_h = (ip_hdr *) (out_buf + sizeof(ethernet_hdr));
  out_ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  out_ip_h->ip_ttl = 64;
  out_ip_h->ip_p = ip_protocol_icmp;
  out_ip_h->ip_dst = ip_h->ip_src;
  out_ip_h->ip_src = ip_h->ip_dst;
  out_ip_h->ip_sum = 0x0;
  out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr));
  icmp_t3_hdr * out_icmp_h = (icmp_t3_hdr *) (out_buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  out_icmp_h->icmp_type = out_icmp_type;
  out_icmp_h->icmp_code = out_icmp_code;
  memcpy(out_icmp_h->data, ip_h, ICMP_DATA_SIZE);
  out_icmp_h->icmp_sum = 0x00;
  out_icmp_h->icmp_sum = cksum(out_icmp_h, sizeof(icmp_t3_hdr));
  Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
  sendPacket(out_packet, iface->name);
  return;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
