/**
 * @file ipk-sniffer.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include <time.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#include "args.h"

#define ERROR -1

#define MAC_LENGTH 17
#define IP_LENGTH 15
#define TIMESTAMP_LENGTH 30
#define MAX_SIZE 100000
#define OFFSET 1000
#define MAX_FILTER_SIZE 512
#define MAX_PROTOCOL_NAME 128

#define ICMP4 1
#define IGMP 2
#define TCP 6
#define UDP 17
#define ICMP6 58
#define NDP 77

struct Output
{
    char *timestamp;
    char *src_mac;
    char *dst_mac;
    int frame_length;
    char *IP;
    char *src_IP;
    char *dst_IP;
    char *protocol;
    char *message_type;
    int src_port;
    int dst_port;
    char *data;
    bool extensions;
};

/**
 * @brief V prípade ukončenia programu pomocou signálu SIGINT korektne ukončí program
 */
void catch_sigint();

/**
 * @brief Naalokuje všetky potrebné dynamické premenné pre beh programu
 * @param arguments Argumenty
 * @param out Štruktúra výstupov
 * @param filter Filter vstupných protokolov
 */
void allocate_resources(struct Arguments **arguments, struct Output **out, char **filter);

/**
 * @brief Uvoľní všetky alokované dynamické premenné pre beh programu
 * @param arguments Argumenty
 * @param out Štruktúra výstupov
 * @param filter Filter vstupných protokolov
 */
void free_resources(struct Arguments *arguments, struct Output *out, char *filter);

/**
 * @brief Vynuluje pamäť zadanú ako argument funkcie o zadanej veľkosti
 *
 * @param memory Pamäť na vynulovanie
 * @param memory_size Veľkosť pamäti na vynulovanie
 */
void null_memory(char *memory, int memory_size);

/**
 * @brief Vynuluje výstupnú štruktúru
 */
void clear_output();

/**
 * @brief Vytvorí Timestamp podľa RFC 3339 formátu
 * @param header Hlavička paketu nutná pre zistenie aktuálnej časovej zóny
 */
void create_timestamp(const struct pcap_pkthdr *header);

/**
 * @brief Podľa vstupného rámca určí výstupnú MAC adresu
 * @param eth_hdr Ethernetová hlavička
 */
void get_mac_adress(struct ether_header *eth_hdr);

/**
 * @brief Vráti dĺžku rámca
 * @param header
 */
void get_frame_length(const struct pcap_pkthdr *header);

/**
 * @brief Nastaví typ IP adresy podľa parametru name
 * @param name
 */
void get_IP_name(char *name);

/**
 * @brief Z IPV4 hlavičky pridá do výstupnej štruktúry IP adresy zdroja a cieľa
 * @param iph IPv4 hlavička
 */
void get_ipv4_header(struct iphdr *iph);

/**
 * @brief Z IPv6 hlavičky pridá do výstupnej štruktúry IP adresy zdroja a cieľa
 * @param iph IPv6 hlavička
 */
void get_ipv6_header(struct ip6_hdr *iph);

/**
 * @brief Nastaví typ protokolu podľa parametru name
 * @param name
 */
void get_protocol_name(char *name);

/**
 * @brief Z TCP hlavičky pridá do výstupnej štruktúry porty zdroja a cieľa
 * @param Buffer Dáta packetu
 */
void get_tcp_port_ipv4(const u_char *Buffer);

/**
 * @brief Z TCP hlavičky pridá do výstupnej štruktúry porty zdroja a cieľa
 * @param iph IPv6 Hlavička
 */
void get_tcp_port_ipv6(struct ip6_hdr *iph);

/**
 * @brief Z UDP hlavičky pridá do výstupnej štruktúry porty zdroja a cieľa
 * @param Buffer Dáta packetu
 */
void get_udp_port_ipv4(const u_char *Buffer);

/**
 * @brief Z UDP hlavičky pridá do výstupnej štruktúry porty zdroja a cieľa
 * @param iph IPv6 Hlavička
 */
void get_udp_port_ipv6(struct ip6_hdr *iph);

/**
 * @brief Nastaví typ správy podľa parametru name
 * @param name
 */
void get_message_type(char *name);

/**
 * @brief Z ARP rámca pridá do výstupnej štruktúry IP adresy zdroja a cieľa
 * @param buffer Dáta packetu
 */
void get_arp_header(const u_char *buffer);

/**
 * @brief Vloži hexadecimálny formát packetu (hex dump) do výstupnej štruktúry
 * @param data Dáta packetu
 * @param size Veľkosť packetu
 */
void get_packet_data(const u_char *data, int size);

/**
 * @brief Vypíše výstupné údaje zo štruktúry Output na štandardný výstup
 */
void print_output(bool ports);

/**
 * @brief Vloží do výstupnej štruktúry všetky potrebné informácie o pakete obsahujúcom IPv4 adresy
 * @param buffer Dáta paketu
 * @param header Hlavička paketu
 */
bool handle_IPv4(const u_char *buffer, const struct pcap_pkthdr *header);

/**
 * @brief Vloží do výstupnej štruktúry všetky potrebné informácie o pakete obsahujúcom IPv6 adresy
 * @param buffer Dáta paketu
 * @param header Hlavička paketu
 */
bool handle_IPv6(const u_char *buffer, const struct pcap_pkthdr *header);

/**
 * @brief Vloží do výstupnej štruktúry všetky potrebné informácie o ARP pakete
 * @param buffer Dáta paketu
 * @param header Hlavička paketu
 */
void handle_ARP(const u_char *buffer, const struct pcap_pkthdr *header);

/**
 * @brief Vypíše konkrétne informácie o pakete podľa jeho typu
 * @param args Argumenty
 * @param header Hlavička paketu
 * @param buffer Dáta paketu
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

/**
 * @brief Podľa zadaných argumentov určí filter, ktorý používaju funkcie pcap_compile() a pcap_setfilter()
 * @param filter Filter
 * @param args Vstupné argumenty
 */
void set_filter(char *filter, struct Arguments *args);

/**
 * @brief Vypíše všetky aktívne rozhrania na aktuálnom zariadení
 */
void print_active_interfaces();
