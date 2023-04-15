/**
 * @file ipk-sniffer.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include <stdio.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "args.h"

#define ERROR -1

#define MAC_LENGTH 17
#define IP_LENGTH 15
#define TIMESTAMP_LENGTH 30

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
    char *src_IP;
    char *dst_IP;
    int src_port;
    int dst_port;
    char *byte_offset;
    char *data;
};

/**
 * @brief Vypíše všetky aktívne rozhrania na aktuálnom zariadení
 */
void print_active_interfaces();

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
 * @brief Vypíše výstupné údaje zo štruktúry Output na štandardný výstup
 */
void print_output(bool ports);

/**
 * @brief Podľa zadaných argumentov určí filter, ktorý používaju funkcie pcap_compile() a pcap_setfilter()
 * @param filter Filter
 * @param args Vstupné argumenty
 */
void set_filter(char *filter, struct Arguments *args);

/**
 * @brief V prípade ukončenia programu pomocou signálu SIGINT korektne ukončí program
 */
void catch_sigint();
