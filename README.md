# IPK projekt 2
## Autor
[Matej Keznikl ( xkezni01 )](https://github.com/kezniklm/)
## Zadanie
Cieľom projektu bolo vytvoriť sieťový analyzátor, ktorý umožňuje zachycovanie a filtrovanie paketov (rámcov) na špecifickom sieťovom rozhraní.

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
$ ../ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
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
Boli testované všetky podporované protokoly, pričom výstup z programu bol porovnávaný pomocou nástroja diff, prípadne ručne s referenčným výstupom z programu **TCPDUMP** alebo **Wireshark**. Pre zaistenie konzistentnosti testovania boli ako prvé pakety zachytené do .pcapng súborov a následne znovu odosielané pomocou nástroja **tcpreplay**.
* **NixOs verzie 22.11.20230221.a3d745e (Raccoon)**
    * Testovanie argumentov programu \
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
    * Testovanie jednotlivých protokolov s parametrom --ext \
        * Testovanie protokolu TCP 
            * Wireshark
                ```
                Src: 00:1d:60:b3:01:84
                Dst: 00:26:62:2f:47:87
                Frame Length: 74 bytes 
                Internet Protocol Version 4
                Src: 192.168.1.3
                Dst: 63.116.243.97
                Transmission Control Protocol
                Src: 58816
                Dst: 80
                
                0000   00 26 62 2f 47 87 00 1d 60 b3 01 84 08 00 45 00   .&b/G...`.....E.
                0010   00 3c a8 cf 40 00 40 06 9d 6b c0 a8 01 03 3f 74   .<..@.@..k....?t
                0020   f3 61 e5 c0 00 50 e5 94 3d aa 00 00 00 00 a0 02   .a...P..=.......
                0030   16 d0 9d e2 00 00 02 04 05 b4 04 02 08 0a 00 17   ................
                0040   95 65 00 00 00 00 01 03 03 07                     .e........


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