/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
} /* -- sr_init -- */

/* get the interface from ip */
struct sr_if *sr_get_interface_from_ip(struct sr_instance *sr, uint32_t ip)
{
    struct sr_if* if_walker = 0;

    if_walker = sr->if_list;

    while(if_walker)
    {
      if(if_walker->ip == ip){
        return if_walker; 
      }
      if_walker = if_walker->next;
    }

    return 0;
} 

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

    /* check minimum length */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Ethernet header is too short\n");
        return;
    }
    struct sr_if *iface = sr_get_interface(sr, interface);
    
    if (ethertype(packet) == ethertype_ip) { /* handle IP packet*/
      /* check the length */
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
          fprintf(stderr, "IP header is too short\n");
          return;
      }

      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      
      /* verify checksum */
      if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
      {
        fprintf(stderr, "checksum does not match\n");
        return;
      }

      /* check the IP version */
      if(ip_hdr->ip_v != 4) {
          fprintf(stderr, "IP is not IPV4\n");
          return;
      }
        
      struct sr_if *dest_interface = sr_get_interface_from_ip(sr, ip_hdr->ip_dst);
      
      if (dest_interface == 0) { /* not find the destination interface */
        if (--ip_hdr->ip_ttl == 0) {
          sr_send_icmp(sr, packet, len, 11, 0); /* TTL=0 means time exceed */
          return;
        }
        /* recalculate the checksum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* get lontgest prefix */
        struct sr_rt* rt_walker = sr->routing_table;
        uint32_t max_mask = 0; /* max match */
        uint32_t mask;
        uint32_t dest;
        uint32_t temp;
        struct sr_rt* rt = NULL;

        while (rt_walker != NULL) {
          mask = rt_walker->mask.s_addr;
          dest = rt_walker->dest.s_addr;
          temp = ip_hdr->ip_dst & mask;
          dest = dest & mask;
          if(temp == dest && mask >= max_mask){ /* update max match */
            rt = rt_walker;
            max_mask = mask;
          }
          rt_walker = rt_walker->next;
        }
        
        if (!rt) { /* there is no entry in routing table */
            sr_send_icmp(sr, packet, len, 3, 0);
            return;
        }
        sr_lookup_arpcache_and_send(sr, packet, len, sr_get_interface(sr, rt->interface), rt->gw.s_addr);
      } else { /*  find the destination interface */
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if (ip_hdr->ip_p == ip_protocol_icmp) {
            /* check icmp length */
            if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_hdr_t)) {
              fprintf(stderr, "ICMP header has insufficient length\n");
              return;
            }
            if (icmp_hdr->icmp_type == 8){ /* this is a icmp echo request */
              sr_send_icmp(sr, packet, len, 0, 0);
            }
            /* this is a tcp or udp */
          } else {
              sr_send_icmp(sr, packet, len, 3, 3);
          }
      }
    } else if (ethertype(packet) == ethertype_arp) { /* handle ARP packet*/
        sr_handle_arp(sr, packet, len, iface);
    }else{
        fprintf(stderr, "Unknown ethertype\n");
    }
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code){
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    

    /* get lontgest prefix */
    struct sr_rt* rt_walker = sr->routing_table;
    uint32_t max_mask = 0; /* max match */
    uint32_t mask;
    uint32_t dest;
    uint32_t temp;
    struct sr_rt* rt = NULL;

    while (rt_walker != NULL) {
      mask = rt_walker->mask.s_addr;
      dest = rt_walker->dest.s_addr;
      temp = ip_hdr->ip_src & mask;
      dest = dest & mask;
      if(temp == dest && mask >= max_mask){ /* update max match */
        rt = rt_walker;
        max_mask = mask;
      }
      rt_walker = rt_walker->next;
    }
    
    if (!rt) {
        fprintf(stderr, "no interface found");
        return;
    }
    
    
    struct sr_if *outgoing_interface = sr_get_interface(sr, rt->interface);
    
    if (icmp_type == 0) { /* echo reply */
        
        memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        
        /* swap source ip and destination ip */
        uint32_t tmp = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = tmp;
        
        
        icmp_hdr->icmp_type = 0;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
       
        sr_lookup_arpcache_and_send(sr, packet, len, outgoing_interface, rt->gw.s_addr);
    }else if (icmp_type == 11 || icmp_type == 3) { /* unreacbabel or time exceed */
        uint8_t *buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        sr_ethernet_hdr_t *eth_response = (sr_ethernet_hdr_t *)buf;
        sr_ip_hdr_t *ip_response = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *icmp_response = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* set created eth response */
        memset(eth_response->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_response->ether_shost, 0, ETHER_ADDR_LEN);
        eth_response->ether_type = htons(ethertype_ip);
        
        /* set created ip response */
        ip_response->ip_v = 4;
        ip_response->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        ip_response->ip_tos = 0;
        ip_response->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip_response->ip_id = htons(0);
        ip_response->ip_off = htons(IP_DF);
        ip_response->ip_ttl = 64;
        ip_response->ip_p = ip_protocol_icmp;
        ip_response->ip_src = (icmp_code == 0 || icmp_code == 1) ? outgoing_interface->ip : ip_hdr->ip_dst;
        ip_response->ip_dst = ip_hdr->ip_src;
        
        ip_response->ip_sum = 0;
        ip_response->ip_sum = cksum(ip_response, sizeof(sr_ip_hdr_t));
        
        /* set created icmp response */
        icmp_response->icmp_type = icmp_type;
        icmp_response->icmp_code = icmp_code;
        icmp_response->unused = 0;
        icmp_response->next_mtu = 0;
        icmp_response->icmp_sum = 0;
        memcpy(icmp_response->data, ip_hdr, ICMP_DATA_SIZE);
        icmp_response->icmp_sum = cksum(icmp_response, sizeof(sr_icmp_t3_hdr_t));
        
        sr_lookup_arpcache_and_send(sr, buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), outgoing_interface, rt->gw.s_addr);
        free(buf);
    }
} 

void sr_lookup_arpcache_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *outgoing_interface, uint32_t ip){
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip);
    
    if (entry) { /* we found it on arpcache, simply send it*/
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, outgoing_interface->name);
        
        free(entry);
    } else { /* not found entry, send it in queue and handle it */
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, outgoing_interface->name);
        
        sr_handle_arpreq(sr, req);
    }
} 



void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface){
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "arp packet has insufficient length\n");
        return;
    }
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *dest_interface = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      if (dest_interface){
        sr_ethernet_hdr_t *buf = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t *eth_res = (sr_ethernet_hdr_t *)buf;
        sr_arp_hdr_t *arp_res = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        /* modify ethernet header */
        memcpy(eth_res->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_res->ether_shost, iface->addr, ETHER_ADDR_LEN);
        eth_res->ether_type = htons(ethertype_arp);
        
        /* modify arp header */
        arp_res->ar_op = htons(arp_op_reply);
        memcpy(arp_res->ar_sha, dest_interface->addr, ETHER_ADDR_LEN);
        memcpy(arp_res->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        arp_res->ar_sip = dest_interface->ip;
        arp_res->ar_tip = arp_hdr->ar_sip;

        /* send the request */
        sr_send_packet(sr, buf, len, iface->name);
        free(buf);
      }
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        if (dest_interface){
          /* add it to arpcache */
          struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
          
          if (req) {
              struct sr_packet * pkt = req->packets;
              /* sequencely send the packet */
              while (pkt) {
                  struct sr_if * outgoing_interface = sr_get_interface(sr, pkt->iface);
                  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                  
                  memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                  memcpy(eth_hdr->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
                  
                  sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                  
                  pkt = pkt->next;
              }
              /* finally destroy the arpreq */
              sr_arpreq_destroy(&(sr->cache), req);
          }
      }
    }
} 


