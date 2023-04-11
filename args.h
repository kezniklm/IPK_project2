/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu ipk-sniffer
 * @date 2023-04-17
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "error.h"

#define FIRST_ARGUMENT 1
#define NEXT_ARGUMENT 1

#define ENDING_ZERO 1
#define MAX_PORT_LENGTH 5
#define MAX_PORT 65535

/**
 * @brief Štruktúra spracovaných argumentov obsahujúca všetky korektne spracované argumenty programu
 */
struct Arguments
{
    bool is_interface;
    char interface[512];
    bool is_port;
    char port[MAX_PORT_LENGTH + ENDING_ZERO];
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
 * @brief Skontroluje a spracuje argumenty programu ipk-sniffer
 *
 * @param argc Počet argumentov
 * @param argv Argumenty programu
 * @param args Štruktúra na uloženie spracovaných argumentov
 */
void arg_check(int argc, char *argv[], struct Arguments *args);

/**
 * @brief Skontroluje prítomnosť a korektnosť druhého argumentu po aktuálnom argumente
 * @param argv Vstupné argumenty
 * @param argument_number Spracovávaný argument
 */
void is_another_argument(char *argv[], int argument_number);

/**
 * @brief Skontroluje formát zadaného portu
 *
 * @param port
 */
void check_port_format(char *port);

/**
 * @brief Skontroluje správnosť formátu počtu packetov
 * @param to_check Reťazec na skontrolovanie
 * @return Počet packetov
 */
int check_number_of_packets(char *to_check);

/**
 * @brief Uvoľní pamäť alokovanú štruktúrou Arguments
 *
 * @param args
 */
void free_arguments(struct Arguments *args);
