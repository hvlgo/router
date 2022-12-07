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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  for (auto iter = m_cacheEntries.begin(); iter != m_cacheEntries.end(); ) {
    if (!(*iter)->isValid) {
      iter = m_cacheEntries.erase(iter);
      continue;
    }
    iter++;
  }

  uint8_t broadcast_mac[ETHER_ADDR_LEN];
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    broadcast_mac[i] = 0xffU;
  }

  for (auto iter = m_arpRequests.begin(); iter != m_arpRequests.end(); ) {
    if ((*iter)->nTimesSent >= MAX_SENT_TIME) {
      PendingPacket tmp = (*iter)->packets.front();
      ethernet_hdr * e_h = (ethernet_hdr *) tmp.packet.data();
      ip_hdr * ip_h = (ip_hdr *) (tmp.packet.data() + sizeof(ethernet_hdr));
      std::cout << ip_h->ip_src << std::endl;
      const Interface * iface = m_router.findIfaceByName(m_router.getRoutingTable().lookup(ip_h->ip_src).ifName);
      
      uint8_t out_buf[sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr)];
      ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
      memcpy(out_e_hdr->ether_dhost, e_h->ether_shost, ETHER_ADDR_LEN);
      memcpy(out_e_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      out_e_hdr->ether_type = htons(ethertype_ip);
      std::cout << "out time" << std::endl;

      memcpy(out_buf + sizeof(ethernet_hdr), ip_h, sizeof(ip_hdr));
      ip_hdr * out_ip_h = (ip_hdr *) (out_buf + sizeof(ethernet_hdr));
      out_ip_h->ip_len = sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
      out_ip_h->ip_ttl = 64;
      out_ip_h->ip_p = ip_protocol_icmp;
      out_ip_h->ip_sum = 0x0;
      out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr));
      out_ip_h->ip_dst = ip_h->ip_src;
      out_ip_h->ip_src = iface->ip;
      icmp_t3_hdr * out_icmp_h = (icmp_t3_hdr *) (out_buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      out_icmp_h->icmp_type = 0x03;
      out_icmp_h->icmp_code = 0x01;
      out_icmp_h->icmp_sum = 0x00;
      out_icmp_h->icmp_sum = cksum(out_icmp_h, sizeof(icmp_t3_hdr));
      Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
      m_router.sendPacket(out_packet, iface->name);
      iter = m_arpRequests.erase(iter);
      continue;
    }

    uint8_t out_buf[sizeof(ethernet_hdr) + sizeof(arp_hdr)];
    const Interface * s_interface = m_router.findIfaceByName((*iter)->packets.front().iface);
    ethernet_hdr * out_e_hdr = (ethernet_hdr *) out_buf;
    memcpy(out_e_hdr->ether_dhost, broadcast_mac, ETHER_ADDR_LEN);
    memcpy(out_e_hdr->ether_shost, s_interface->addr.data(), ETHER_ADDR_LEN);
    out_e_hdr->ether_type = htons(ethertype_arp);
    arp_hdr * out_arp_h = (arp_hdr *) (out_buf + sizeof(ethernet_hdr));
    out_arp_h->arp_hrd = htons(arp_hrd_ethernet);
    out_arp_h->arp_pro = htons(ethertype_ip);
    out_arp_h->arp_hln = ETHER_ADDR_LEN;
    out_arp_h->arp_pln = sizeof(uint32_t);
    out_arp_h->arp_op = htons(arp_op_request);
    memcpy(out_arp_h->arp_sha, s_interface->addr.data(), ETHER_ADDR_LEN);
    out_arp_h->arp_sip = s_interface->ip;
    memcpy(out_arp_h->arp_tha, broadcast_mac, ETHER_ADDR_LEN);
    out_arp_h->arp_tip = (*iter)->ip;

    Buffer out_packet(out_buf, out_buf + sizeof(out_buf));
    m_router.sendPacket(out_packet, s_interface->name);

    (*iter)->nTimesSent++;
    (*iter)->timeSent = std::chrono::steady_clock::now();
    iter++;
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
