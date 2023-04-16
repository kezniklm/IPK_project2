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
        Špecifikuje počet paketov, ktoré majú byť zobrazené. V prípade chýbajúce argumentu sa počet paketov na zobrazenie rovná 1

    Pokiaľ nie sú protokoly špecifikované, všetky z nich môžu byť zachytené a následne vypísané.
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

## Popis implementácie


## Zdroje
<a id="ref1"></a> [1] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 4)

<a id="ref2"></a> [2] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 3)

<a id="ref3"></a> [3] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 1)

<a id="ref4"></a> [4] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 4.3.3)

<a id="ref5"></a> [5] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 5)

<a id="ref6"></a> [6] Kurose, J. F., & Ross, K. W. (2017). Computer Networking: A Top-Down Approach. Pearson. (Kapitola 7)