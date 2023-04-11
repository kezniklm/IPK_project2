/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia spracovania argumentov programu ipk-sniffer
 * @date 2023-03-21
 */

#include "args.h"

 /**
 * @brief Uvoľní pamäť alokovanú štruktúrou Arguments
 *
 * @param args
 */
void free_arguments(struct Arguments *args)
{
    free(args);
}