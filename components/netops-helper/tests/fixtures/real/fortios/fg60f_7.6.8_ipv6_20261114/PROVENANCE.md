# Skutečné IPv6 CLI capture, lab FG-60F

Datum14.11.2026, UTC02:37:50–02:38:09. FortiGate-60F v7.6.8 build3744 (GA.M), NAT, VDOMdisable/root, HAstandalone, IPv6VRF=0. ČtyřiROget, každérc0 a stderr0; žádnázměna zařízeníažádnýping/debug. Příkazy: get system status; get router info6 routing-table; get router info6 routing-table ::1; get router info6 routing-table 2001:db8:ffff:ffff::dead.

01-version je systemstatus s explicitněanonymizovanýmSerial-Number (nástrojzprvu tento hyphenatedlabelnepoznal,proto--serialzrawhodnotypředuložením); skutečnésériovéčíslo neníuveřejněné. Všechny4stdout zpracovány jednímběhemzavedenéhoanonymizeru--check--serialbezmap,rc0. CRLF bylynormalizované naLF. 02–04jinakshodné seskutečnýmstdout. NejdeosyntetickéIPv6route. 03:connectedloopback::1/128, best, distance0/metric0, direktroot. 04:explicitní%Networknotintable, nikolivodmítnutípříkazu/emptytransport. 02neobsahujeIPv6default.

Prokázánjedenconnectedloopbacklookup a jedenno-route na tomtofirmwaru. NejdeokvalifikaciIPv6forwardingu/statických/BGP/ECMP/rekurzivníchtras aniMultiVDOM/jinýchFW. Změněné/syntetickécasevtestechmusíbýt označenéjakoderived,ne novéliveměření. ZdrojovéoperatorTASKevidence jeinterníprovoz109-09/capture-82, nepatřídoproduktu.

SHA256pořadí01–04:
01-version.txt 2529569982965cccc40c0313bad4ac76610c14004c3ec947adae168f665b48ec
02-ipv6-routing-table.txt 7b5e204596ac6516f7b23e77b553556dae046fe8aa4986c1256dd3a76a82f565
03-lookup-loopback.txt 1ef247f0a9a1b24cc76ac97238e0d01e07595a2fe231543f686d2a3b9d56470a
04-lookup-documentation-address.txt 4d884c8d7dd32cf32e463fc46fdcfc750c356705fc2e6f681fda6a063dfed883
