/**
 * @file ipk-sniffer.c
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include "ipk-sniffer.h"

struct Output *out;

/**
 * @brief V prípade ukončenia programu pomocou signálu SIGINT korektne ukončí program
 *
 */
void catch_sigint()
{
    exit(SIGINT);
}

/**
 * @brief Naalokuje všetky potrebné dynamické premenné pre beh programu
 * @param arguments Argumenty
 * @param out Štruktúra výstupov
 * @param filter Filter vstupných protokolov
 */
void allocate_resources(struct Arguments **arguments, struct Output **out, char **filter)
{
    *arguments = calloc(1, sizeof(struct Arguments));
    *out = calloc(1, sizeof(struct Output));
    (*out)->timestamp = calloc(TIMESTAMP_LENGTH, sizeof(char));
    (*out)->src_mac = calloc(MAC_LENGTH + ENDING_ZERO, sizeof(char));
    (*out)->dst_mac = calloc(MAC_LENGTH + ENDING_ZERO, sizeof(char));
    (*out)->src_IP = calloc(IP_LENGTH + ENDING_ZERO, sizeof(char));
    (*out)->dst_IP = calloc(IP_LENGTH + ENDING_ZERO, sizeof(char));

    *filter = calloc(512, sizeof(char));

    if (!*arguments || !*filter || !*out || !(*out)->src_mac || !(*out)->dst_mac || !(*out)->src_IP || !(*out)->dst_IP)
    {
        error_exit("Chyba pri alokácii pamäte");
    }
}

/**
 * @brief Uvoľní všetky alokované dynamické premenné pre beh programu
 * @param arguments Argumenty
 * @param out Štruktúra výstupov
 * @param filter Filter vstupných protokolov
 */
void free_resources(struct Arguments *arguments, struct Output *out, char *filter)
{
    if (arguments)
    {
        free_arguments(arguments);
    }

    if (out)
    {
        if (out->timestamp)
        {
            free(out->timestamp);
        }
        if (out->src_mac)
        {
            free(out->src_mac);
        }

        if (out->dst_mac)
        {
            free(out->dst_mac);
        }

        if (out->src_IP)
        {
            free(out->src_IP);
        }

        if (out->dst_IP)
        {
            free(out->dst_IP);
        }
        free(out);
    }

    if (filter)
    {
        free(filter);
    }
}

/**
 * @brief Vynuluje pamäť zadanú ako argument funkcie o zadanej veľkosti
 *
 * @param memory Pamäť na vynulovanie
 * @param memory_size Veľkosť pamäti na vynulovanie
 */
void null_memory(char *memory, int memory_size)
{
    memset(memory, '\0', memory_size);
}

/**
 * @brief Vynuluje výstupnú štruktúru
 */
void clear_output()
{
    null_memory(out->timestamp, TIMESTAMP_LENGTH);
    null_memory(out->src_mac, MAC_LENGTH + ENDING_ZERO);
    null_memory(out->dst_mac, MAC_LENGTH + ENDING_ZERO);
    // null_memory(out->frame_length,strlen(out->frame_length));
    null_memory(out->src_IP, IP_LENGTH + ENDING_ZERO);
    null_memory(out->dst_IP, IP_LENGTH + ENDING_ZERO);
    // null_memory(out->src_port,strlen(out->src_port));
    // null_memory(out->dst_port,strlen(out->dst_port));
    // null_memory(out->byte_offset,strlen(out->byte_offset));
}

/**
 * @brief Vytvorí Timestamp podľa RFC 3339 formátu
 * @param header Hlavička paketu nutná pre zistenie aktuálnej časovej zóny
 */
void create_timestamp(const struct pcap_pkthdr *header)
{
    time_t timestamp = header->ts.tv_sec;
    struct tm *local_time = localtime(&timestamp);
    char timestamp_str[40], microsecond_str[5], timezone_offset[7], timezone_offset_without_semicolon[7];

    // Vytvorí timestamp string v RFC 3339 formáte
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%S", local_time);

    // Pripojí mikrosekundovú časť ku timestamp stringu
    if (snprintf(microsecond_str, sizeof(microsecond_str), ".%03ld", header->ts.tv_usec) < 0)
    {
        error_exit("Chyba vramci funkcie snprintf"); //snprintf
    }
    strncat(timestamp_str, microsecond_str, sizeof(timestamp_str) - strlen(timestamp_str) - 1);

    // Pripojí timezone offset k timestamp stringu
    strftime(timezone_offset_without_semicolon, sizeof(timezone_offset_without_semicolon), "%z", local_time);
    null_memory(timezone_offset, 7);
    strncpy(timezone_offset, timezone_offset_without_semicolon, 3);
    timezone_offset[3] = ':';
    strcat(timezone_offset, timezone_offset_without_semicolon + 3);
    strncat(timestamp_str, timezone_offset, sizeof(timestamp_str) - strlen(timestamp_str) - 1);

    strcpy(out->timestamp, timestamp_str);
}

void get_mac_adress(struct ether_header *eth_hdr)
{
    char source_mac[18], dest_mac[18];

    // Konvertuje zdrojovu MAC adresu na string
    sprintf(source_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    // Konvertuje cielovu MAC adresu na string
    sprintf(dest_mac, "%02x:%02x:%02x:%02x:%02x:%02x", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    strcpy(out->src_mac,source_mac);
    strcpy(out->dst_mac,dest_mac);
}

void get_frame_length(const struct pcap_pkthdr *header)
{
    out->frame_length = header->len;
}

/**
 * @brief Vypíše výstupné údaje zo štruktúry Output na štandardný výstup
 */
void print_output()
{
    printf("timestamp: %s\n", out->timestamp);
    printf("src MAC: %s\n",out->src_mac);
    printf("dst MAC: %s\n",out->dst_mac);
    printf("frame length: %d bytes\n",out->frame_length);
    fflush(stdout);
}

/**
 * @brief
 * @param args
 * @param header
 * @param buffer
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    static int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, arp = 0, ndp = 0, icmp6 = 0;
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    clear_output();
    create_timestamp(header);
    get_mac_adress(eth_hdr);
    get_frame_length(header);
    print_output();
    ++total;
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
    {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        switch (iph->protocol)
        {
        case ICMP4:
            // print_icmp4();
            ++icmp;
            break;

        case IGMP:
            // print_igmp();
            ++igmp;
            break;

        case TCP:
            // print_tcp();
            ++tcp;
            break;

        case UDP:
            ++udp;
            // print_udp();
            break;
        default:
            printf("\n%d\n", iph->protocol);
            ++others;
            break;
        }
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
    {
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
        int protocol = iph->ip6_nxt;
        unsigned char icmpv6_type = *(buffer + sizeof(struct ip6_hdr));
        switch (protocol)
        {
        case TCP:
            // print_tcp();
            ++tcp;
            break;

        case UDP:
            ++udp;
            // print_udp();
            break;

        case ICMP6_MLD:
            ++icmp6;
            // print_icmp6_or_mld();
            break;

        default:
            printf("\n%d\n", protocol);
            ++others;
            break;
        }
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
    {
        ++arp;
        // print_arp();
    }
    else
    {
        printf("Unknown packet type\n");
    }
    printf("TCP : %d   UDP : %d   ICMP4 : %d  ARP: %d NDP:%d IGMP : %d MLD: %d   Others : %d   Total : %d\n", tcp, udp, icmp, arp, ndp, igmp, icmp6, others, total);
    fflush(stdout);
}

/**
 * @brief Podľa zadaných argumentov určí filter, ktorý používaju funkcie pcap_compile() a pcap_setfilter()
 * @param filter Filter
 * @param args Vstupné argumenty
 */
void set_filter(char *filter, struct Arguments *args)
{
    if (!filter || !args)
    {
        error_exit("Filter a argumenty nemozu byt NULL");
    }
    if (args->tcp == true)
    {
        strcpy(filter, "tcp port ");
        strcat(filter, args->port);
        strcat(filter, " ");
    }
    if (args->udp == true)
    {
        strcpy(filter, "udp port ");
        strcat(filter, args->port);
        strcat(filter, " ");
    }
    if (args->arp == true)
    {
        if (args->tcp || args->udp)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "arp ");
    }
    if (args->icmp4 == true)
    {
        if (args->tcp || args->udp || args->arp)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "ip proto 1 ");
    }
    if (args->icmp6 == true)
    {
        if (args->tcp || args->udp || args->arp || args->icmp4)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "icmp6 ");
    }
    if (args->igmp == true)
    {
        if (args->tcp || args->udp || args->arp || args->icmp4 || args->icmp6)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "igmp ");
    }
    if (args->mld == true)
    {
        if (args->tcp || args->udp || args->arp || args->icmp4 || args->icmp6 || args->igmp)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "(icmp6[icmp6type] == 130 or icmp6[icmp6type] == 131 or icmp6[icmp6type] == 132) or (icmp6 and ip6[40] == 143) ");
    }
    if (args->ndp == true)
    {
        if (args->tcp || args->udp || args->arp || args->icmp4 || args->icmp6 || args->igmp || args->mld)
        {
            strcat(filter, "or ");
        }
        strcat(filter, "((icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137) or (icmp6[icmp6type] == 139)) ");
    }

    if (!args->tcp && !args->udp && !args->arp && !args->icmp4 && !args->icmp6 && !args->igmp && !args->mld && !args->ndp)
    {
        strcat(filter, "tcp or udp or arp or ip proto 1 or icmp6 or igmp or (icmp6[icmp6type] == 130 or icmp6[icmp6type] == 131 or icmp6[icmp6type] == 132) or (icmp6 and ip6[40] == 143) or ((icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137) or (icmp6[icmp6type] == 139))");
    }
}

/**
 * @brief Vypíše všetky aktívne rozhrania na aktuálnom zariadení
 */
void print_active_interfaces(char *errbuff)
{
    pcap_if_t *interface_list, *interface;

    if (pcap_findalldevs(&interface_list, errbuff) == ERROR)
    {
        error_exit("Nie je mozne vypisat vsetky rozhrania\n");
    }

    for (interface = interface_list; interface != NULL; interface = interface->next)
    {
        printf("%s\n", interface->name);
    }

    pcap_freealldevs(interface_list);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    /* Zachytenie CTRL+C (SIGINT) */
    signal(SIGINT, catch_sigint);

    struct Arguments *arguments;
    struct bpf_program fp;
    char *filter, errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *opened_session;
    bpf_u_int32 pMask, pNet;

    allocate_resources(&arguments, &out, &filter);
    arg_check(argc, argv, arguments);
    if (arguments->is_interface == false)
    {
        print_active_interfaces(errbuff);
    }

    // printf("interface:%s\n", arguments->interface);
    // printf("port:%s\n", arguments->port);
    // printf("tcp:%d\n", arguments->tcp);
    // printf("udp:%d\n", arguments->udp);
    // printf("icmp4:%d\n", arguments->icmp4);
    // printf("icmp6:%d\n", arguments->icmp6);
    // printf("arp:%d\n", arguments->arp);
    // printf("ndp:%d\n", arguments->ndp);
    // printf("igmp:%d\n", arguments->igmp);
    // printf("mld:%d\n", arguments->mld);
    // printf("number_of_packets:%d\n", arguments->number_of_packets);

    if (pcap_lookupnet(arguments->interface, &pNet, &pMask, errbuff) == ERROR)
    {
        error_exit("Nepodarilo sa získať sieťovú masku");
    }

    opened_session = pcap_open_live(arguments->interface, BUFSIZ, 1, 1000, errbuff);
    if (opened_session == NULL)
    {
        error_exit("Nebolo možné otvoriť zadaný interface");
    }

    set_filter(filter, arguments);
    // printf("%s", filter);
    // fflush(stdout);
    if (pcap_compile(opened_session, &fp, filter, 0, pNet) == ERROR)
    {
        error_exit("Zlyhanie funkcie pcap_compile");
    }

    if (pcap_setfilter(opened_session, &fp) == ERROR)
    {
        error_exit("Nie je možné použiť daný filter");
    }

    pcap_loop(opened_session, arguments->number_of_packets, packet_handler, (u_char *)&out);

    free_resources(arguments, out, filter);
    pcap_close(opened_session);
    exit(EXIT_SUCCESS);
}