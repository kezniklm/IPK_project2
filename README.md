# Network Sniffer
## Autor
[Matej Keznikl ( xkezni01 )](https://github.com/kezniklm/)
## Zadanie
Cieľom projektu bolo vytvoriť sieťový analyzátor, ktorý umožňuje zachycovanie a filtrovanie paketov (rámcov) na špecifickom sieťovom rozhraní.

## Výsledné hodnotenie
20/20 bodov + 1 bonusový bod

## Implementácia 

Projekt je implementovaný v jazyku C, revízia C18 (ISO/IEC 9899:2018). Doporučuje sa prekladač **gcc verzie 7.5.0** a jeho novšie vydania.

## Použité knižnice potrebné k prekladu
* time.h
* pcap.h
* stdio.h
* signal.h
* stdarg.h
* string.h
* stdlib.h
* stdbool.h
* netinet/ether.h
* netinet/ip6.h
* netinet/tcp.h
* netinet/ip_icmp.h
* netinet/udp.h
* netinet/icmp6.h

## Preklad 
Preloženie projektu je možné programom GNU Make, zadaním príkazu **```make```**, pričom je nutné pred preložením projektu **```rozbaliť```** zip archív.

```
$ unzip xkezni01.zip
$ make
```
## Spustenie
Projekt je spúšťaný z príkazovej riadky, pričom prepínače je možné vzájomne zameniť.
```
$ ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num} [--ext]
    -i eth0 alebo --interface eth0
        V prípade zadaného rozhrania bude dané rozhranie analyzované.
        Pokiaľ tento parameter nie je špecifikovaný (ani žiadnen ostatný), alebo            
        je parameter je špecifikovaný bez hodnoty a ostatné parametre nie sú 
        špecifikované, vypíše list dostupných rozhraní
    -t alebo --tcp
        Zobrazí TCP segmenty
    -u alebo --udp
        Zobrazí UDP datagramy
    -p <číslo>
        Rozširuje predchádzajúce dva parametre na filtráciu TCP/UDP na konkrétnom porte.
    --icmp4
        Zobrazí iba ICMPv4 pakety
    --icmp6
        Zobrazí iba ICMPv6 pakety, konkrétne echo request/response
    --arp
        Zobrazí iba ARP rámce
    --ndp
        Zobrazí iba ICMPv6 NDP pakety
    --igmp
        Zobrazí iba IGMP pakety
    --mld
        Zobrazí iba MLD pakety 
    -n <číslo>
        Špecifikuje počet paketov, ktoré majú byť zobrazené. V prípade 
        chýbajúceho argumentu sa počet paketov na zobrazenie rovná 1
    --ext 
        Zobrazí dodatočné a zároveň detailnejšie výpisy - jedná sa o                
        rozšírenie

    Pokiaľ nie sú protokoly špecifikované, všetky z nich môžu byť zachytené a 
    následne vypísané.
    Všetky argumenty môžu byť v hociakom poradí.
```
## Príklady použitia
```
./ipk-sniffer -i eth0 -p 23 --tcp -n 2
./ipk-sniffer -i eth0 --udp
./ipk-sniffer -i eth0 --igmp --mld -n 10   
./ipk-sniffer -i eth0 --icmp4 --icmp6
./ipk-sniffer -i eth0 --arp --ndp
./ipk-sniffer -i eth0 -n 10      
./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp4 --icmp6 --arp --ndp --igmp --mld
./ipk-sniffer -i eth0
```

## Príklad funkcionality
```
./ipk-sniffer

lo0
eth0

./ipk-sniffer -i

lo0
eth0

./ipk-sniffer -i eth0
timestamp: 2023-04-16T22:29:30.594+02:00
src MAC: 00:1d:60:b3:01:84
dst MAC: 00:26:62:2f:47:87
frame length: 74 bytes
IPv4
src IP: 192.168.1.3
dst IP: 63.116.243.97
Transmission Control Protocol
src port: 58816
dst port: 80

0x0000:  00 26 62 2F 47 87 00 1D 60 B3 01 84 08 00 45 00         .&b/G...`.....E.
0x0010:  00 3C A8 CF 40 00 40 06 9D 6B C0 A8 01 03 3F 74         .<..@.@..k....?t
0x0020:  F3 61 E5 C0 00 50 E5 94 3D AA 00 00 00 00 A0 02         .a...P..=.......
0x0030:  16 D0 9D E2 00 00 02 04 05 B4 04 02 08 0A 00 17         ................
0x0040:  95 65 00 00 00 00 01 03 03 07                           .e........
```
## Teoretické základy

* **IP adresa** *(Internet Protocol Address)* je číselná adresa, ktorá identifikuje zariadenie pripojené k počítačovej sieti. Každé zariadenie, ktoré je pripojené k internetu, má pridelenú **jedinečnú** IP adresu, ktorá sa skladá z dvoch častí: **adresy siete** a **adresy rozhrania**. Adresa siete označuje sieť, do ktorej zariadenie patrí, zatiaľ čo adresa rozhrania identifikuje samotné zariadenie v rámci danej siete. IP adresa sa v súčasnosti používa vo verzii **IPv4** alebo **IPv6**, kde IPv6 používa dlhšiu číselnú sekvenciu a umožňuje tak viacero možností pre pridelenie unikátnych adries [[1](#ref1)].

* **Rámec** *(Frame)* je základnou jednotkou dát, ktoré sú prenášané v počítačovej sieti na fyzickej vrstve. Každý rámec obsahuje dáta a riadiace informácie, vrátane zdrojovej a cieľovej adresy, typu dát a kontrolného súčtu. Zdrojová a cieľová adresa v rámci sú fyzické adresy, ktoré sa zvyčajne nazývajú MAC adresy (Media Access Control). Typ dát v rámci označuje, aký typ dát sa prenáša v rámci, napríklad IP paket alebo ARP (Address Resolution Protocol) rámec. Kontrolný súčet slúži na kontrolu chýb v rámci a zabezpečuje, že dáta boli správne prenesené z jedného zariadenia na druhé [[9](#ref9)].

* **Paket** *(Packet)* môže byť definovaný ako blok údajov, ktoré sú prenášané cez sieť z jedného uzla do druhého. Tieto údaje môžu zahŕňať rôzne informácie, ako sú napríklad užitočné dáta aplikácie, hlavičky protokolov a kontrolné súčty.
Hlavička paketu obsahuje dôležité informácie o pakete, ako napríklad zdrojovú a cieľovú adresu, identifikátor protokolu a kontrolné súčty. Tieto informácie sú použité na správne doručenie paketu na jeho cieľovú adresu a overenie jeho správnej prijateľnosti. Okrem užitočných dát môže paket obsahovať aj informácie o spôsobe spracovania a doručenia paketu cez sieť. Tieto informácie sa zvyčajne nachádzajú v hlavičkách protokolov, ktoré sú umiestnené medzi užitočnými dátami a sieťovou vrstvou [[8](#ref8)].

* **Zapúzdrenie** - v počítačových sieťach sa dáta prenášajú v jednotlivých paketoch. Každý paket má dve základné časti - hlavičku a telo. Hlavička obsahuje informácie potrebné na doručenie paketu na správne miesto v sieti, ako sú zdrojová a cieľová adresa, kontrolné súčty a dĺžka paketu. Telo paketu obsahuje samotné dáta, ktoré sa prenášajú. Pri prenose dát cez sieť sa každý paket zapúzdruje, teda obalí sa do nového paketu, ktorý obsahuje adresu cieľovej stanice. Tento proces sa opakuje na každom medzietape, až kým sa paket nedostane na cieľovú staniciu. Tam sa paket rozbalí a dáta sa spracujú. Zapúzdrenie umožňuje prenos dát medzi rôznymi sieťovými vrstvami a zabezpečuje ich spoľahlivý prenos v sieti [[10](#ref10)].

* **TCP** *(Transmission Control Protocol)*. Jedná sa o protokol pre spoľahlivý prenos dát v počítačových sieťach. TCP zabezpečuje, že dáta sú **správne doručené** medzi dvoma zariadeniami v sieti a že sú doručené v **správnom poradí**.
TCP funguje tak, že dáta sú rozdelené na menšie kúsky nazývané segmenty a každý segment je označený číslom sekvencie. Tieto segmenty sú potom posielané cez sieť, pričom sú overované na správnosť doručenia a poradia pomocou čísel sekvencií. TCP tiež využíva techniku nazývanú potvrdenie, ktorá zabezpečuje, že zariadenie, ktoré prijalo dáta, pošle späť potvrdenie o doručení týchto dát. Ak sa potvrdenie nevráti v určenom čase, TCP znovu pošle segment, aby zabezpečil správne doručenie [[2](#ref2)].

* **UDP** *(User Datagram Protocol)*. Jedná sa o protokol pre prenos datagramov v počítačových sieťach, ktorý poskytuje **nespoľahlivý**, **nezabezpečený** a **bezstavový** prenos dát. Oproti TCP, UDP nezabezpečuje správne doručenie dát, ich poradie ani potvrdenie doručenia, avšak vďaka týmto obmedzeniam dosahuje rýchlejší prenos dát s menšou reťazou oneskorení. Protokol UDP sa používa najmä v aplikáciách, ktoré vyžadujú rýchle prenosy dát, ako sú napríklad online hry, multimediálne streamovacie aplikácie alebo DNS (Domain Name System) servery [[2](#ref2)].

* **Port** je číslo, ktoré identifikuje konkrétnu službu na zariadení pripojenom k počítačovej sieti. V TCP/IP modeli je port definovaný ako 16-bitové číslo (t.j. číslo od 0 do 65535), ktoré sa skladá z čísla portu a čísla protokolu, s ktorým je port asociovaný. Existuje množstvo preddefinovaných portov, ktoré sú asociované so štandardnými protokolmi, ako napríklad port 80 pre HTTP, port 25 pre SMTP alebo port 53 pre DNS. Okrem toho, používatelia môžu definovať aj vlastné porty pre vlastné služby [[2](#ref2)].

* **Rozhranie** *(network interface)* v počítačovej sieti slúži ako miesto, kde sa zariadenie pripája k sieti. Základnou funkciou rozhrania je prenos dát medzi zariadením a sieťou. Rozhranie má svoju hardvérovú a softvérovú časť. Hardvérová časť je zvyčajne karta siete alebo port na smerovači, ktorý umožňuje pripojenie k sieti. Softvérová časť pozostáva z ovládačov a protokolov, ktoré umožňujú komunikáciu medzi rozhraním a operačným systémom. Rozhranie môže byť konfigurované pre rôzne parametre, ako sú napríklad IP adresa, maska siete, brána a DNS server. Tieto parametre sú dôležité pre správne fungovanie komunikácie medzi zariadeniami v sieti [[3](#ref3)].

* **ICMPv4** *(Internet Control Message Protocol version 4)* je protokol používaný v počítačových sieťach na riadenie a správu chybových správ a informačných správ. ICMPv4 poskytuje sieťovým zariadeniam informácie o chybových stavoch a ich príčinách, čím pomáha zlepšovať kvalitu komunikácie a diagnostikovať problémy v sieti [[2](#ref2)].

* **ICMPv6** *(Internet Control Message Protocol version 6)* je protokol, ktorý slúži na správu a kontrolu sieťovej komunikácie v IPv6 sieti. Podobne ako ICMPv4, ktorý sa používa v sietiach s protokolom IPv4, aj ICMPv6 poskytuje informácie o chybových stavoch, doručovaní paketov a rôzne diagnostické informácie. ICMPv6 protokol poskytuje rôzne typy správ, vrátane správ o stave siete, správ o chybových stavoch, správ o retransmisii paketov a správ o doručení paketov. Okrem toho existujú aj špeciálne typy správ, ako napríklad Neighbor Discovery Protocol (NDP) a Multicast Listener Discovery (MLD), ktoré slúžia na získavanie informácií o susedných zariadeniach v sieti [[4](#ref4)].

* **ARP** *(Address Resolution Protocol)* je protokol používaný v počítačových sieťach na mapovanie sieťových adries (IP adries) na fyzické adresy (MAC adresy). V rámci IP komunikácie sa dáta posielajú na základe IP adries, ale aby mohli byť správne doručené, musia byť správne mapované na fyzické adresy v rámci danej siete. ARP je používaný pre túto úlohu [[5](#ref5)].

* **NDP** *(Neighbor Discovery Protocol)* je protokol, ktorý sa používa v IPv6 sieťach na zistenie susedov v sieti, získanie ich MAC adries a smerovačov pre doručovanie paketov. NDP je analógom protokolu ARP (Address Resolution Protocol), ktorý sa používa v IPv4 sieťach na riešenie rovnakých problémov [[5](#ref5)].

* **IGMP** *(Internet Group Management Protocol)* je protokol, ktorý sa používa na správu skupín IP multicastu v počítačovej sieti. Jeho úlohou je umožniť zariadeniam v sieti dynamicky sa pridávať alebo odstraňovať zo skupín IP multicastu podľa potreby [[1](#ref1)].

* **MLD** *(Multicast Listener Discovery)* je protokol, ktorý sa používa na získanie informácií o multicast skupinách, ktoré sú dostupné v sieti a na určenie, ktoré zariadenia sú členmi týchto skupín. MLD protokol umožňuje multicastovým routovacím protokolom zistiť, ktoré linky v sieti majú záujem o multicastový tok a tým minimalizovať množstvo nevyžiadanej prevádzky [[6](#ref6)].

* **PCAP** *(Packet Capture)* je jednou z najrozšírenejších softvérových knižníc používaných na zachytávanie a analýzu sieťových paketov. Používa sa pre rôzne účely, ako sú sieťová bezpečnosť, sieťové testovanie a ladenie aplikácií.
PCAP umožňuje aplikáciám zachytávať pakety na rôznych sieťových rozhraniach a spracovávať ich pomocou jazykov ako C a Python. Poskytuje tiež funkcie pre filtrovanie paketov na základe rôznych kritérií, ako sú zdrojová adresa, cieľová adresa, typ protokolu a port. Knižnica pcap bola pôvodne vyvinutá pre Unixové operačné systémy, no existujú aj porty pre Windows a iné operačné systémy. Populárna sieťová analytická aplikácia Wireshark používa knižnicu pcap na zachytávanie a analýzu paketov [[7](#ref7)].

## Popis implementácie

* **Overenie argumentov programu** \
Program ako prvé skontroluje správnosť argumentov programu, čo zahŕňa overenie čísla portu tak aby bol v intervale <0,65535>, overenie aby počet paketov n bol integer a celkovo korektnosť zápisu všetkých argumentov. V prípade, že bolo zadané väčšie množstvo argumentov, neexistujúci argument alebo zlý formát daného argumentu tak program skončí s chybovou hláškou podľa danej chyby.
V prípade úspešného spracovania argumentov budú argumenty uložené v štruktúre **Arguments**. Overenie argumentov zaisťujú funkcie z **args.h** implementované v **args.c** a chybové hlášky a korektné ukončenie programu zaisťujú funkcie z **error.h** implementované v **error.c**.

* **Implementácia sieťového analyzéra (sniffera)** \
Ako prvé sa zo štruktúry **Arguments** načítajú argumenty programu. Následne sa v prípade, že nebolo zadané žiadne rozhranie vypíšu všetky dostupné rozhrania. V prípade, že bolo zadané konkrétne rozhranie, je získaná jeho sieťová maska pomocou funkcie **pcap_lookupnet()**. V prípade úspešného získania sieťovej masky je dané rozhranie otvorené pomocou funkcie **pcap_open_live()** a taktiež je overené pomocou funkcie **pcap_datalink()**, že sa jedná o ethernetové rozhranie. Funkcia **set_filter()** nastaví filter podľa zadaný argumentov, tzn. podľa obsahu štruktúry **Arguments**. Funkcia **pcap_setfilter()** daný filter nastaví na filtrovanie. Následne **pcap_loop()** iteruje skrz pakety (rámce), ktoré budú splňovať podmienky filtrovania. Funkcia **pcap_loop()** v rámci iterovania volá pre každý paket (rámec) funkciu **packet_handler()**, ktorá podľa typu ethernetového rámca volá funkcie **handle_IPv4()** pre IPv4, **handle_IPv6()** pre IPv6 a **handle_ARP()** pre ARP.

## Rozšírenia
Implementácia je rozšírená o prepínač **--ext**, ktorá umožňuje výpis dodatočných informácii o packetoch. Implementácia taktiež podporuje **Jumbo rámce** o typickej veľkosti 9000 bytov.

## Testovanie
Testovanie bolo vykonávané na operačných systémoch Ubuntu a referenčnom NixOS, kde boli zdrojové súbory preložené pomocou GCC 11.3.0 .
Boli testované všetky podporované protokoly, pričom výstup z programu bol porovnávaný pomocou test.py, prípadne ručne s referenčným výstupom z programu **TCPDUMP** alebo **Wireshark**. Pre zaistenie konzistentnosti testovania boli ako prvé pakety zachytené do .pcapng súborov a následne znovu odosielané pomocou nástroja **tcpreplay**.
Následne boli porovnané výsledné verzie medzi sebou pomocou skriptu **test.py**, ktorý porovnával výstup programu **Wireshark** (.src súbory) a **ipk-sniffer** (.out súbory). V prípade úspešného porovnania je výsledok prázdny reťazec "".
* **NixOs verzie 22.11.20230221.a3d745e (Raccoon)**
    * Testovanie argumentov programu
        * Výpis všetkých dostupných rozhraní
            * TCPDUMP
                ```
                $sudo tcpdump -D
                    1.enp0s3 [Up, Running, Connected]
                    2.any (Pseudo-device that captures on all interfaces) 
                    [Up, Running]
                    3.lo [Up, Running, Loopback]
                    4.nflog (Linux netfilter log (NFLOG) interface) [none]
                    5.nfqueue (Linux netfilter queue (NFQUEUE) interface) [none]
                ```
            * ipk-sniffer
                ```
                $ sudo ./ipk-sniffer
                    enp0s3
                    any
                    lo
                    nflog
                    nfqueue
                ```
                ```
                $ sudo ./ipk-sniffer -i
                    enp0s3
                    any
                    lo
                    nflog
                    nfqueue
                ```
                ```
                $ sudo ./ipk-sniffer --interface
                    enp0s3
                    any
                    lo
                    nflog
                    nfqueue
                ```
        
        Ďalšie testovanie argumentov bolo vykonávané vzájomne s testovanim jednotlivých protokolov, preto už dalšie testovanie argumentov neuvádzam.
    * Testovanie jednotlivých protokolov s parametrom --ext (timestamp nebol testovaný) 
        * Testovanie protokolu TCP 
            * Wireshark (súbor TCP.src)
                ```
                src MAC: 00:1d:60:b3:01:84
                dst MAC: 00:26:62:2f:47:87
                frame length: 74 bytes 
                Internet Protocol Version 4
                src IP: 192.168.1.3
                dst IP: 63.116.243.97
                Transmission Control Protocol
                src port: 58816
                dst port: 80
                
                0x0000:   00 26 62 2f 47 87 00 1d 60 b3 01 84 08 00 45 00   .&b/G...`.....E.
                0x0010:   00 3c a8 cf 40 00 40 06 9d 6b c0 a8 01 03 3f 74   .<..@.@..k....?t
                0x0020:   f3 61 e5 c0 00 50 e5 94 3d aa 00 00 00 00 a0 02   .a...P..=.......
                0x0030:   16 d0 9d e2 00 00 02 04 05 b4 04 02 08 0a 00 17   ................
                0x0040:   95 65 00 00 00 00 01 03 03 07                     .e........
                ```
            * ipk-sniffer (súbor TCP.out)
               ```
                timestamp: 2023-04-17T17:52:39.817+02:00
                src MAC: 00:1d:60:b3:01:84
                dst MAC: 00:26:62:2f:47:87
                frame length: 74 bytes
                Internet Protocol Version 4
                src IP: 192.168.1.3
                dst IP: 63.116.243.97
                Transmission Control Protocol
                src port: 58816
                dst port: 80

                0x0000:  00 26 62 2F 47 87 00 1D 60 B3 01 84 08 00 45 00         .&b/G...`.....E.
                0x0010:  00 3C A8 CF 40 00 40 06 9D 6B C0 A8 01 03 3F 74         .<..@.@..k....?t
                0x0020:  F3 61 E5 C0 00 50 E5 94 3D AA 00 00 00 00 A0 02         .a...P..=.......
                0x0030:  16 D0 9D E2 00 00 02 04 05 B4 04 02 08 0A 00 17         ................
                0x0040:  95 65 00 00 00 00 01 03 03 07                           .e........
               ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu UDP 
            * Wireshark (súbor UDP.src)
                ```
                src MAC: 00:14:0b:33:33:27
                dst MAC: d0:7a:b5:96:cd:0a
                frame length: 109 bytes
                Internet Protocol Version 4
                src IP: 192.168.1.101
                dst IP: 178.123.13.120
                User Datagram Protocol
                src port: 42559
                dst port: 26895

                0x0000:   d0 7a b5 96 cd 0a 00 14 0b 33 33 27 08 00 45 00   .z.......33'..E.
                0x0010:   00 5f 31 16 00 00 80 11 87 77 c0 a8 01 65 b2 7b   ._1......w...e.{
                0x0020:   0d 78 a6 3f 69 0f 00 4b 6a 54 64 31 3a 61 64 32   .x.?i..KjTd1:ad2
                0x0030:   3a 69 64 32 30 3a 5a fa 29 99 3a 5e ce 19 d1 8b   :id20:Z.).:^....
                0x0040:   aa 9b 4e 4d f9 2e 51 52 fe ff 65 31 3a 71 34 3a   ..NM..QR..e1:q4:
                0x0050:   70 69 6e 67 31 3a 74 34 3a 85 72 00 00 31 3a 76   ping1:t4:.r..1:v
                0x0060:   34 3a 55 54 7e 62 31 3a 79 31 3a 71 65            4:UT~b1:y1:qe
                ```
            * ipk-sniffer (súbor UDP.out)
                ```
                timestamp: 2023-04-17T19:15:03.594+02:00
                src MAC: 00:14:0b:33:33:27
                dst MAC: d0:7a:b5:96:cd:0a
                frame length: 109 bytes
                Internet Protocol Version 4
                src IP: 192.168.1.101
                dst IP: 178.123.13.120
                User Datagram Protocol
                src port: 42559
                dst port: 26895

                0x0000:  D0 7A B5 96 CD 0A 00 14 0B 33 33 27 08 00 45 00         .z.......33'..E.
                0x0010:  00 5F 31 16 00 00 80 11 87 77 C0 A8 01 65 B2 7B         ._1......w...e.{
                0x0020:  0D 78 A6 3F 69 0F 00 4B 6A 54 64 31 3A 61 64 32         .x.?i..KjTd1:ad2
                0x0030:  3A 69 64 32 30 3A 5A FA 29 99 3A 5E CE 19 D1 8B         :id20:Z.).:^....
                0x0040:  AA 9B 4E 4D F9 2E 51 52 FE FF 65 31 3A 71 34 3A         ..NM..QR..e1:q4:
                0x0050:  70 69 6E 67 31 3A 74 34 3A 85 72 00 00 31 3A 76         ping1:t4:.r..1:v
                0x0060:  34 3A 55 54 7E 62 31 3A 79 31 3A 71 65                  4:UT~b1:y1:qe
                ```
            * Výstup testu
                ``````
        * Testovanie protokolu ICMPv4 
            * Wireshark (súbor ICMPv4.src)
                ``` 
                src MAC: ca:01:59:d6:00:08
                dst MAC: 52:54:00:a7:a5:80
                frame length: 114 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.33
                dst IP: 192.168.122.1
                Internet Control Message Protocol version 4

                0x0000:   52 54 00 a7 a5 80 ca 01 59 d6 00 08 08 00 45 00   RT......Y.....E.
                0x0010:   00 64 00 04 00 00 ff 01 46 21 c0 a8 7a 21 c0 a8   .d......F!..z!..
                0x0020:   7a 01 08 00 38 73 00 00 00 04 00 00 00 00 00 03   z...8s..........
                0x0030:   45 d0 ab cd ab cd ab cd ab cd ab cd ab cd ab cd   E...............
                0x0040:   ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd   ................
                0x0050:   ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd   ................
                0x0060:   ab cd ab cd ab cd ab cd ab cd ab cd ab cd ab cd   ................
                0x0070:   ab cd                                             ..
                ```     
            * ipk-sniffer (súbor ICMPv4.out)
                ``` 
                timestamp: 2023-04-17T19:25:25.198+02:00
                src MAC: ca:01:59:d6:00:08
                dst MAC: 52:54:00:a7:a5:80
                frame length: 114 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.33
                dst IP: 192.168.122.1
                Internet Control Message Protocol version 4

                0x0000:  52 54 00 A7 A5 80 CA 01 59 D6 00 08 08 00 45 00         RT......Y.....E.
                0x0010:  00 64 00 04 00 00 FF 01 46 21 C0 A8 7A 21 C0 A8         .d......F!..z!..
                0x0020:  7A 01 08 00 38 73 00 00 00 04 00 00 00 00 00 03         z...8s..........
                0x0030:  45 D0 AB CD AB CD AB CD AB CD AB CD AB CD AB CD         E...............
                0x0040:  AB CD AB CD AB CD AB CD AB CD AB CD AB CD AB CD         ................
                0x0050:  AB CD AB CD AB CD AB CD AB CD AB CD AB CD AB CD         ................
                0x0060:  AB CD AB CD AB CD AB CD AB CD AB CD AB CD AB CD         ................
                0x0070:  AB CD                                                   ..
                ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu ICMPv6 
            * Wireshark (súbor ICMPv6.src)
                ``` 
                src MAC: 54:e1:ad:c1:2d:ee
                dst MAC: 30:9c:23:28:c7:7a
                frame length: 118 bytes
                Internet Protocol Version 6
                src IP: fe80::8f8a:681d:7918:7cab
                dst IP: fe80::2d5:8ff8:38e:894
                Internet Control Message Protocol version 6
                ICMPv6 Echo Reply

                0x0000:   30 9c 23 28 c7 7a 54 e1 ad c1 2d ee 86 dd 60 00   0.#(.zT...-...`.
                0x0010:   c8 49 00 40 3a 40 fe 80 00 00 00 00 00 00 8f 8a   .I.@:@..........
                0x0020:   68 1d 79 18 7c ab fe 80 00 00 00 00 00 00 02 d5   h.y.|...........
                0x0030:   8f f8 03 8e 08 94 81 00 12 b1 00 28 00 07 56 d1   ...........(..V.
                0x0040:   3a 64 00 00 00 00 8d 3f 05 00 00 00 00 00 10 11   :d.....?........
                0x0050:   12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21   .............. !
                0x0060:   22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31   "#$%&'()*+,-./01
                0x0070:   32 33 34 35 36 37                                 234567
                ```     
            * ipk-sniffer (súbor ICMPv6.out)
                ``` 
                timestamp: 2023-04-17T19:41:56.506+02:00
                src MAC: 54:e1:ad:c1:2d:ee
                dst MAC: 30:9c:23:28:c7:7a
                frame length: 118 bytes
                Internet Protocol Version 6
                src IP: fe80::8f8a:681d:7918:7cab
                dst IP: fe80::2d5:8ff8:38e:894
                Internet Control Message Protocol version 6
                ICMPv6 Echo Reply

                0x0000:  30 9C 23 28 C7 7A 54 E1 AD C1 2D EE 86 DD 60 00         0.#(.zT...-...`.
                0x0010:  C8 49 00 40 3A 40 FE 80 00 00 00 00 00 00 8F 8A         .I.@:@..........
                0x0020:  68 1D 79 18 7C AB FE 80 00 00 00 00 00 00 02 D5         h.y.|...........
                0x0030:  8F F8 03 8E 08 94 81 00 12 B1 00 28 00 07 56 D1         ...........(..V.
                0x0040:  3A 64 00 00 00 00 8D 3F 05 00 00 00 00 00 10 11         :d.....?........
                0x0050:  12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21         .............. !
                0x0060:  22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31         "#$%&'()*+,-./01
                0x0070:  32 33 34 35 36 37                                       234567
                
                ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu ARP 
            * Wireshark (súbor ARP.src)
                ``` 
                src MAC: 52:54:00:a7:a5:80
                dst MAC: ff:ff:ff:ff:ff:ff
                frame length: 42 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.1
                dst IP: 85.163.14.54
                Address Resolution Protocol

                0x0000:   ff ff ff ff ff ff 52 54 00 a7 a5 80 08 06 00 01   ......RT........
                0x0010:   08 00 06 04 00 01 52 54 00 a7 a5 80 c0 a8 7a 01   ......RT......z.
                0x0020:   00 00 00 00 00 00 55 a3 0e 36                     ......U..6
                ```     
            * ipk-sniffer (súbor ARP.out)
                ``` 
                timestamp: 2023-04-17T19:45:21.320+02:00
                src MAC: 52:54:00:a7:a5:80
                dst MAC: ff:ff:ff:ff:ff:ff
                frame length: 42 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.1
                dst IP: 85.163.14.54
                Address Resolution Protocol

                0x0000:  FF FF FF FF FF FF 52 54 00 A7 A5 80 08 06 00 01         ......RT........
                0x0010:  08 00 06 04 00 01 52 54 00 A7 A5 80 C0 A8 7A 01         ......RT......z.
                0x0020:  00 00 00 00 00 00 55 A3 0E 36                           ......U..6
                ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu NDP
            * Wireshark (súbor NDP.src)
                ``` 
                src MAC: ca:01:59:d6:00:08
                dst MAC: 33:33:ff:d7:93:df
                frame length: 86 bytes
                Internet Protocol Version 6
                src IP: fe80::c801:59ff:fed6:8
                dst IP: ff02::1:ffd7:93df
                Neighbor Discovery Protocol
                NDP Neighbor Solicitation

                0x0000:   33 33 ff d7 93 df ca 01 59 d6 00 08 86 dd 6e 00   33......Y.....n.
                0x0010:   00 00 00 20 3a ff fe 80 00 00 00 00 00 00 c8 01   ... :...........
                0x0020:   59 ff fe d6 00 08 ff 02 00 00 00 00 00 00 00 00   Y...............
                0x0030:   00 01 ff d7 93 df 87 00 76 37 00 00 00 00 fe 80   ........v7......
                0x0040:   00 00 00 00 00 00 48 38 51 ff fe d7 93 df 01 01   ......H8Q.......
                0x0050:   ca 01 59 d6 00 08                                 ..Y...
                ```     
            * ipk-sniffer (súbor NDP.out)
                ``` 
                timestamp: 2023-04-17T19:48:15.152+02:00
                src MAC: ca:01:59:d6:00:08
                dst MAC: 33:33:ff:d7:93:df
                frame length: 86 bytes
                Internet Protocol Version 6
                src IP: fe80::c801:59ff:fed6:8
                dst IP: ff02::1:ffd7:93df
                Neighbor Discovery Protocol
                NDP Neighbor Solicitation

                0x0000:  33 33 FF D7 93 DF CA 01 59 D6 00 08 86 DD 6E 00         33......Y.....n.
                0x0010:  00 00 00 20 3A FF FE 80 00 00 00 00 00 00 C8 01         ... :...........
                0x0020:  59 FF FE D6 00 08 FF 02 00 00 00 00 00 00 00 00         Y...............
                0x0030:  00 01 FF D7 93 DF 87 00 76 37 00 00 00 00 FE 80         ........v7......
                0x0040:  00 00 00 00 00 00 48 38 51 FF FE D7 93 DF 01 01         ......H8Q.......
                0x0050:  CA 01 59 D6 00 08                                       ..Y...
                ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu IGMP
            * Wireshark (súbor IGMP.src)
                ``` 
                src MAC: 52:54:00:a7:a5:80
                dst MAC: 01:00:5e:00:00:16
                frame length: 54 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.1
                dst IP: 224.0.0.22
                Internet Group Management Protocol

                0x0000:   01 00 5e 00 00 16 52 54 00 a7 a5 80 08 00 46 c0   ..^...RT......F.
                0x0010:   00 28 00 00 40 00 01 02 c9 4f c0 a8 7a 01 e0 00   .(..@....O..z...
                0x0020:   00 16 94 04 00 00 22 00 ea 03 00 00 00 01 04 00   ......".........
                0x0030:   00 00 ef ff ff fa                                 ......
                ```     
            * ipk-sniffer (súbor IGMP.out)
                ``` 
                timestamp: 2023-04-17T19:50:31.817+02:00
                src MAC: 52:54:00:a7:a5:80
                dst MAC: 01:00:5e:00:00:16
                frame length: 54 bytes
                Internet Protocol Version 4
                src IP: 192.168.122.1
                dst IP: 224.0.0.22
                Internet Group Management Protocol

                0x0000:  01 00 5E 00 00 16 52 54 00 A7 A5 80 08 00 46 C0         ..^...RT......F.
                0x0010:  00 28 00 00 40 00 01 02 C9 4F C0 A8 7A 01 E0 00         .(..@....O..z...
                0x0020:  00 16 94 04 00 00 22 00 EA 03 00 00 00 01 04 00         ......".........
                0x0030:  00 00 EF FF FF FA                                       ......
                ``` 
            * Výstup testu
                ``````
        * Testovanie protokolu MLD
            * Wireshark (súbor MLD.src)
                ``` 
                src MAC: 08:00:27:56:aa:92
                dst MAC: 33:33:00:00:00:16
                frame length: 78 bytes
                Internet Protocol Version 6
                src IP: 2001:db8::1
                dst IP: ff02::16
                Multicast Listener Discovery
                MLD Listener Query

                0x0000:   33 33 00 00 00 16 08 00 27 56 aa 92 86 dd 60 00   33......'V....`.
                0x0010:   00 00 00 18 3a 01 20 01 0d b8 00 00 00 00 00 00   ....:. .........
                0x0020:   00 00 00 00 00 01 ff 02 00 00 00 00 00 00 00 00   ................
                0x0030:   00 00 00 00 00 16 82 00 29 ca 27 10 00 00 00 00   ........).'.....
                0x0040:   00 00 00 00 00 00 00 00 00 00 00 00 00 00         ..............
                ```     
            * ipk-sniffer (súbor MLD.out)
                ``` 
                timestamp: 2023-04-17T19:54:14.330+02:00
                src MAC: 08:00:27:56:aa:92
                dst MAC: 33:33:00:00:00:16
                frame length: 78 bytes
                Internet Protocol Version 6
                src IP: 2001:db8::1
                dst IP: ff02::16
                Multicast Listener Discovery
                MLD Listener Query

                0x0000:  33 33 00 00 00 16 08 00 27 56 AA 92 86 DD 60 00         33......'V....`.
                0x0010:  00 00 00 18 3A 01 20 01 0D B8 00 00 00 00 00 00         ....:. .........
                0x0020:  00 00 00 00 00 01 FF 02 00 00 00 00 00 00 00 00         ................
                0x0030:  00 00 00 00 00 16 82 00 29 CA 27 10 00 00 00 00         ........).'.....
                0x0040:  00 00 00 00 00 00 00 00 00 00 00 00 00 00               ..............
                ``` 
            * Výstup testu
                ```
                ```       

* **Ubuntu 22.04.2 LTS - WSL** \
Testovanie na operačnom systéme **Ubuntu 22.04.2 LTS** bolo vykonané s rovnakými vstupmi ako na **NixOs verzie 22.11.20230221.a3d745e (Raccoon)** pričom sa ukázalo, že všetky výstupy sú totožné. Z toho dôvodu ukážky z testovania neuvádzam.

## Zdroje
<a id="ref1"></a> [1] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 4)

<a id="ref2"></a> [2] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 3)

<a id="ref3"></a> [3] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 1)

<a id="ref4"></a> [4] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 4.3.3)

<a id="ref5"></a> [5] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 5)

<a id="ref6"></a> [6] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 7)

<a id="ref7"></a>[7] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 2.5)

<a id="ref8"></a>[8] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 2.2)

<a id="ref8"></a>[9] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 2)

<a id="ref10"></a>[10] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 1.3.3)
