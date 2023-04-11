/**
 * @file ipk-sniffer.c
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include "ipk-sniffer.h"

/**
 * @brief Vypíše všetky aktívne rozhrania na aktuálnom zariadení
 */
void print_active_interfaces()
{
    char errbuff[PCAP_ERRBUF_SIZE];
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
}

int main(int argc, char *argv[])
{
    struct Arguments *arguments = calloc(1, sizeof(struct Arguments));
    if (!arguments)
    {
        error_exit("Chyba pri alokácii pamäte");
    }
    arg_check(argc, argv, arguments);
    if (arguments->is_interface == false)
    {
        print_active_interfaces();
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
    free_arguments(arguments);
}