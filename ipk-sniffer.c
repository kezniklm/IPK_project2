/**
 * @file ipk-sniffer.c
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include "ipk-sniffer.h"

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
 * @brief
 * @param args
 * @param header
 * @param buffer
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    static int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, arp = 0, ndp = 0, icmp6 = 0;
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    
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
                printf("\n%d\n",iph->protocol);
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
                printf("\n%d\n",protocol);
                ++others;
                break;
        }
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
    {
        ++arp;
        // print_arp();
        return;
    }
    else {
        printf("Unknown packet type\n");
    }
    printf("TCP : %d   UDP : %d   ICMP4 : %d  ARP: %d NDP:%d IGMP : %d MLD: %d   Others : %d   Total : %d\r", tcp, udp, icmp, arp, ndp, igmp, icmp6, others, total);
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
    struct Output *out;
    struct bpf_program fp;
    char *filter;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *opened_session;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;

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

    pcap_loop(opened_session, arguments->number_of_packets, packet_handler, NULL);

    free_resources(arguments, out, filter);
    exit(EXIT_SUCCESS);
}