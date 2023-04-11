/**
 * @file ipk-sniffer.c
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia sieťového sniffera
 * @date 2023-04-17
 */

#include "ipk-sniffer.h"

int main(int argc, char *argv[])
{
    struct Arguments *arguments = calloc(1, sizeof(struct Arguments));
    if (!arguments)
    {
        error_exit("Chyba pri alokácii pamäte");
    }
    arg_check(argc, argv, arguments);
    free_arguments(arguments);
}