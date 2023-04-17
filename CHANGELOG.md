# IPK projekt 2
## Autor 
[Matej Keznikl ( xkezni01 )](https://github.com/kezniklm/)

## Implementácia 
Projekt je implementovaný v jazyku C, revízia C18 (ISO/IEC 9899:2018). Doporučuje sa prekladač **gcc verzie 7.5.0** a jeho novšie vydania.

V rámci projektu bol implementovaný sieťový analyzátor, ktorý umožňuje zachycovanie a filtrovanie paketov (rámcov) na špecifickom sieťovom rozhraní.

## Limitácie
* Maximálna dĺžka packetov
    * Maximálna dĺžka podporovaných packetov je 10048 bytov, pričom pri väčších packetoch je program ukončený chybovou hláškou.