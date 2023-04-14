/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia spracovania argumentov programu ipk-sniffer
 * @date 2023-04-17
 */

#include "args.h"

/**
 * @brief Skontroluje a spracuje argumenty programu ipk-sniffer
 *
 * @param argc Počet argumentov
 * @param argv Argumenty programu
 * @param args Štruktúra na uloženie spracovaných argumentov
 */
void arg_check(int argc, char *argv[], struct Arguments *args)
{
    if (!argv)
    {
        error_exit("Pole argumentov nemôže byť NULL");
    }
    for (int argument = FIRST_ARGUMENT; argument < argc; argument++)
    {
        if (!strcmp(argv[argument], "--help") || !strcmp(argv[argument], "-h"))
        {
            printf("Názov:\n    ipk-sniffer - sieťový analyzátor\n\nPoužitie:\n  ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n\n  ./ipk-sniffer --help \n\n  ./ipk-sniffer --h \nPopis:\n    Sieťový analyzátor, ktorý umožňuje zachycovať a filtrovať pakety pre špecifické sieťové rozhranie.\n");
            free(args);
            exit(EXIT_SUCCESS);
        }
        else if (!strcmp(argv[argument], "-i") || !strcmp(argv[argument], "--interface"))
        {
            if (argv[argument + NEXT_ARGUMENT] != NULL && argv[argument + NEXT_ARGUMENT][0] != '-')
            {
                args->is_interface = true;
                strcpy(args->interface, argv[argument + NEXT_ARGUMENT]);
                argument++;
            }
        }
        else if (!strcmp(argv[argument], "-p"))
        {
            is_another_argument(argv, argument);
            strncpy(args->port, argv[argument + 1], MAX_PORT_LENGTH + ENDING_ZERO);
            check_port_format(argv[argument + 1]);
            args->is_port = true;
            argument++;
            if (!strcmp(argv[argument + 1], "-t") || !strcmp(argv[argument + 1], "--tcp"))
            {
                args->tcp = true;
                argument++;
            }
            else if (!strcmp(argv[argument + 1], "-u") || !strcmp(argv[argument + 1], "--udp"))
            {
                args->udp = true;
                argument++;
            }
        }
        else if (!strcmp(argv[argument], "--icmp4"))
        {
            args->icmp4 = true;
        }
        else if (!strcmp(argv[argument], "--icmp6"))
        {
            args->icmp6 = true;
        }
        else if (!strcmp(argv[argument], "--arp"))
        {
            args->arp = true;
        }
        else if (!strcmp(argv[argument], "--ndp"))
        {
            args->ndp = true;
        }
        else if (!strcmp(argv[argument], "--igmp"))
        {
            args->igmp = true;
        }
        else if (!strcmp(argv[argument], "--mld"))
        {
            args->mld = true;
        }
        else if (!strcmp(argv[argument], "-n"))
        {
            is_another_argument(argv, argument);
            args->number_of_packets = check_number_of_packets(argv[argument + NEXT_ARGUMENT]);
            argument++;
        }
        else
        {
            error_exit("Chybný argument programu. Vyskúšajte ./ipk-sniffer --help\n");
        }
    }

    // Nastavenie východzej hodnoty počtu paketov
    if (args->number_of_packets == 0)
    {
        args->number_of_packets = 1;
    }
}

/**
 * @brief Skontroluje prítomnosť a korektnosť druhého argumentu po aktuálnom argumente
 * @param argv Vstupné argumenty
 * @param argument_number Spracovávaný argument
 */
void is_another_argument(char *argv[], int argument_number)
{
    if (argv[argument_number + NEXT_ARGUMENT] != NULL)
    {
        if (argv[argument_number + NEXT_ARGUMENT][0] == '-')
            error_exit("Chybný argument programu");
    }
    else
    {
        error_exit("Chybný argument programu");
    }
}

/**
 * @brief Skontroluje formát zadaného portu
 *
 * @param port Port, ktorý má byť skontrolovaný
 */
void check_port_format(char *port)
{
    if (!port || strlen(port) > MAX_PORT_LENGTH)
    {
        error_exit("Port nemá požadovaný formát\n");
    }
    char *tmp;
    int int_port = strtol(port, &tmp, 10);

    if (strcmp(tmp, "") != 0 || int_port < 0 || int_port > MAX_PORT)
    {
        error_exit("Port nemá požadovaný formát\n");
    }
}

/**
 * @brief Skontroluje správnosť formátu počtu packetov
 * @param to_check Reťazec na skontrolovanie
 * @return Počet packetov
 */
int check_number_of_packets(char *to_check)
{
    char *tmp;
    int packet_number = strtol(to_check, &tmp, 10);
    if (strcmp(tmp, "") != 0 || packet_number < 0)
    {
        error_exit("Chybný počet packetov na vyzobrazenie");
    }
    return packet_number;
}

/**
 * @brief Uvoľní pamäť alokovanú štruktúrou Arguments
 *
 * @param args
 */
void free_arguments(struct Arguments *args)
{
    free(args);
}