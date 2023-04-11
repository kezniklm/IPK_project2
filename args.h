/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu ipk-sniffer
 * @date 2023-03-21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "error.h"

/**
 * @brief Štruktúra spracovaných argumentov obsahujúca všetky korektne spracované argumenty programu
 */
struct Arguments
{
    bool isInterface;
    char interface[512];
    bool tcp;
    bool udp;
    bool icmp4;
    bool icmp6;
    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
    int number_of_packets;
};

/**
 * @brief Uvoľní pamäť alokovanú štruktúrou Arguments
 * 
 * @param args 
 */
void free_arguments(struct Arguments *args);

 