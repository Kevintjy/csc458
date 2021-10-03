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

struct sr_if *sr_get_interface_from_addr(struct sr_instance *sr, const unsigned char *addr);
struct sr_if *sr_get_interface_from_ip(struct sr_instance *sr, uint32_t ip_nbo);
static void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code);

static void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip);
struct sr_rt *sr_longest_prefix_match_lookup(struct sr_instance *sr, uint32_t ip);
static void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface);
static void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip);

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
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    struct sr_if *iface = sr_get_interface(sr, interface);
    
    if (ethertype(packet) == ethertype_ip) { /* handle IP packet*/
      /* check the length */
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
          fprintf(stderr, "IP header is too short\n");
          return;
      }

      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      
      /* verify checksum */
      if (cksum(ip_hdr, ip_hdr->ip_hl * 4) != 0xffff)
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
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
        /* get lontgest prefix of destination ip*/
        struct sr_rt* rt_walker = sr->routing_table;
        uint32_t max_mask = 0;
        uint32_t mask;
        uint32_t dest;
        uint32_t temp;
        struct sr_rt* rt = NULL;

        while (rt_walker != NULL) {
          mask = rt_walker->mask.s_addr;
          dest = rt_walker->dest.s_addr;
          temp = ip_hdr->ip_dst & mask;
          dest = dest & mask;
          if(temp == dest && mask >= max_mask){
            rt = rt_walker;
            max_mask = mask;
          }
          rt_walker = rt_walker->next;
        }
        
        if (!rt) { /* there is no entry in routing table */
            sr_send_icmp(sr, packet, len, 3, 0);
            return;
        }

        struct sr_if *oiface = sr_get_interface(sr, rt->interface);
        sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
      } else { /*  find the destination interface */
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if (ip_hdr->ip_p == ip_protocol_icmp) {
            if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(sr_icmp_hdr_t)) {
              fprintf(stderr, "ICMP header has insufficient length\n");
              return;
            }
            if (icmp_hdr->icmp_type == 8){ /* this is a icmp echo request */
              sr_send_icmp(sr, packet, len, 0, 0);
            }

          } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 11) {
              sr_send_icmp(sr, packet, len, 3, 3);
          }else{
            fprintf(stderr, "reach unknown state");
          }
      }
    } else if (ethertype(packet) == ethertype_arp) { /* handle ARP packet*/
        sr_handle_arp(sr, packet, len, iface);
    }else{
        fprintf(stderr, "Unknown ethertype\n");
    }
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
    assert(sr);
    assert(packet);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    int icmp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    

    /* get lontgest prefix of src ip*/
    struct sr_rt* rt_walker = sr->routing_table;
    uint32_t max_mask = 0;
    uint32_t mask;
    uint32_t dest;
    uint32_t temp;
    struct sr_rt* rt = NULL;

    while (rt_walker != NULL) {
      mask = rt_walker->mask.s_addr;
      dest = rt_walker->dest.s_addr;
      temp = ip_hdr->ip_src & mask;
      dest = dest & mask;
      if(temp == dest && mask >= max_mask){
        rt = rt_walker;
        max_mask = mask;
      }
      rt_walker = rt_walker->next;
    }
    
    if (!rt) {
        fprintf(stderr, "there is no rt");
        return;
    }
    struct sr_if *oiface = sr_get_interface(sr, rt->interface);
    
    if (type == 0) { /* echo reply */
        memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        
        /* exchange ip src and dst */
        uint32_t tmp = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = tmp;
        /* set the type and code */
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        /* recalculate the checksum */
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
       
        sr_lookup_and_send(sr, packet, len, oiface, rt->gw.s_addr);
    } else if (type == 3 || type == 11) {
        /* malloc space for new response */
        uint8_t *buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        /* set the eth respnse header */
        sr_ethernet_hdr_t *eth_res_hdr = (sr_ethernet_hdr_t *)buf;
        memset(eth_res_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
        memset(eth_res_hdr->ether_shost, 0, ETHER_ADDR_LEN);
        eth_res_hdr->ether_type = htons(ethertype_ip);

        /* set the ip respnse header */
        sr_ip_hdr_t *ip_res_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        ip_res_hdr->ip_v = 4;
        ip_res_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        ip_res_hdr->ip_tos = 0;
        ip_res_hdr->ip_id = 0;
        ip_res_hdr->ip_off = IP_DF;
        ip_res_hdr->ip_ttl = 100;
        ip_res_hdr->ip_p = ip_protocol_icmp;
        ip_res_hdr->ip_src = (code == 0 || code == 1) ? oiface->ip : ip_hdr->ip_dst;
        ip_res_hdr->ip_dst = ip_hdr->ip_src;
        ip_res_hdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        ip_res_hdr->ip_sum = 0;
        ip_res_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        
        /* set the icmp respnse header */
        sr_icmp_t3_hdr_t *icmp_res_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_res_hdr->icmp_type = type;
        icmp_res_hdr->icmp_code = code;
        icmp_res_hdr->icmp_sum = 0;
        icmp_res_hdr->next_mtu = 0;
        icmp_res_hdr->unused = 0;
        memcpy(icmp_res_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        icmp_res_hdr->icmp_sum = cksum(icmp_res_hdr, sizeof(sr_icmp_t3_hdr_t));
        
        sr_lookup_and_send(sr, buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), oiface, rt->gw.s_addr);
        free(buf);
    } else{
      fprintf(stderr, "get into error state\n");
    }
} /* -- sr_send_icmp -- */

void sr_lookup_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *oiface, uint32_t ip)
{
    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip);
    
    if (entry) { /* if the entry is in arp cache */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, packet, len, oiface->name);
        
        free(entry);
    } else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip, packet, len, oiface->name);
        
        sr_handle_arpreq(sr, req);
    }
} /* -- sr_lookup_and_send -- */

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
{
    assert(sr);
    assert(req);
    
    if (difftime(time(NULL), req->sent) >= 1.0) {
        if (req->times_sent >= 5) {
            struct sr_packet *pkt = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            struct sr_if *iface = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                iface = sr_get_interface_from_addr(sr, eth_hdr->ether_dhost);
                
                /* do not send an ICMP message for an ICMP message */
                if (iface) {
                    sr_send_icmp(sr, pkt->buf, pkt->len, 3, 1);
                }
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            struct sr_if *oiface = sr_get_interface(sr, req->packets->iface);
            
            sr_send_arp_request(sr, oiface, req->ip);
            
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
} /* -- sr_handle_arpreq -- */

void sr_handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    assert(sr);
    assert(packet);
    assert(iface);
    
    /* check length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "Failed to process ARP header, insufficient length\n");
        return;
    }
    
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* print_hdr_arp((uint8_t *)arp_hdr); */
    
    /* check hardware type */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        return;
    }
    
    /* check protocol */
    if (ntohs(arp_hdr->ar_pro) != ethertype_ip) {
        return;
    }
    
    /* is it for me? */
    struct sr_if *tiface = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
    
    if (!tiface) {
        return;
    }
    
    unsigned short arp_op = ntohs(arp_hdr->ar_op);
    
    if (arp_op == arp_op_request) {
        sr_send_arp_reply(sr, packet, iface, tiface);
    } else if (arp_op == arp_op_reply) {
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if (req) {
            struct sr_packet *pkt = NULL;
            struct sr_if *oiface = NULL;
            sr_ethernet_hdr_t *eth_hdr = NULL;
            
            pkt = req->packets;
            
            while (pkt) {
                oiface = sr_get_interface(sr, pkt->iface);
                
                eth_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
                
                memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
                
                sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
                
                pkt = pkt->next;
            }
            
            sr_arpreq_destroy(&(sr->cache), req);
        }
    }
} /* -- sr_handle_arp -- */

void sr_send_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *oiface, struct sr_if *tiface)
{
    assert(sr);
    assert(packet);
    assert(oiface);
    assert(tiface);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
    
    /* arp header */
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    new_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, tiface->addr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip = tiface->ip;
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_reply -- */

void sr_send_arp_request(struct sr_instance *sr, struct sr_if *oiface, uint32_t tip)
{
    assert(sr);
    assert(oiface);
    
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    
    /* ethernet header */
    memset(eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, oiface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);
    
    /* arp header */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, oiface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = oiface->ip;
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = tip;
    
    /* print_hdrs(buf, len); */
    sr_send_packet(sr, buf, len, oiface->name);
    free(buf);
} /* -- sr_send_arp_request -- */

struct sr_rt *sr_longest_prefix_match_lookup(struct sr_instance *sr, uint32_t ip)
{
  struct sr_rt* rt_walker = sr->routing_table;
  
  uint32_t max_mask = 0;
  uint32_t mask;
  uint32_t dest;
  uint32_t temp;
  struct sr_rt* ret = NULL;

  while (rt_walker != NULL) {
    mask = rt_walker->mask.s_addr;
    dest = rt_walker->dest.s_addr;
    temp = ip & mask;
    dest = dest & mask;
    if(temp == dest && mask >= max_mask){
      ret = rt_walker;
      max_mask = mask;
    }
    rt_walker = rt_walker->next;
  }
  return ret; 
}

struct sr_if *sr_get_interface_from_addr(struct sr_instance *sr, const unsigned char *addr)
{
    struct sr_if *if_walker = 0;
    
    assert(addr);
    assert(sr);
    
    if_walker = sr->if_list;
    
    while (if_walker) {
        if (!memcmp(if_walker->addr, addr, ETHER_ADDR_LEN)) {
            return if_walker;
        }
        
        if_walker = if_walker->next;
    }
    
    return 0;
} /* -- sr_get_interface_from_addr -- */

