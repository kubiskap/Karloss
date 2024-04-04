# Karloss_v2
This software was created as a part of my bachelor thesis. It aims is to provide C-ITS message verification.

Requirements:
* packages: asn1tools, pyshark, json
* software: Wireshark

**Momentalni stav je takovyto:**

* _plugins/msg.py_ - obsahuje objekt ItsMessage s procedurami **get_dictionary** (vrati slovnik kompilovany z asn souboru) a **decode** (dekoduje data dle asn slovniku), zobecnene pro ruzne typy zprav
* _pktImport.py_ - obsahuje funkce **get_msg_types** (vytvori objekty ItsMessage pro typy zprav definovane v souboru config.json - je tam definovany port, nazev zpravy a soubory ASN ktere se k jejimu dekodovani maji pouzit) a **get_packet_array** (vrati list dekodovanych paketu ze souboru pcap, nyni je tam i osetreni vyjimek DecodeError a ConstraintsError a promenne ktere mi slouzily jako statistiky pri debugovani tohoto problemu)
* _testing.py_ - zde je muj pokus o analyzu jednotlivych paketu, funkce **extract_asn_all_parameters** (ze slovniku kompilovaneho z asn vytahne vsechny parametry jejichz definice jsou schovane pod nejakou SEQUENCE nebo jinym datovym typem kde jsou nejaci "members"), **summary_add_value** (prida bud varovani, OK stav nebo error do summary podobne jako v puvodnim Karlossovi) a **recursive_msg_parameters** (ze zpravy rekurzivne vytahne vsechny parametry a jejich hodnoty do slovniku)
  * dale je tam zatim nezabaleny ve funkci samotny algoritmus, kterym jsem vyhodnocoval pro kazdy paket jednotlive datove typy parametru, pripadne prirazoval named-numbers, named-bits apod.
  * kdyz tento soubor spustite, spusti se ta analyza pro soubor test.pcap (z ukazky, 184 paketu) a vysledky se ulozi do promennych "summary" a "pktsAnalysed"
  testing_kapsch_consignia.py - test dekodovani jednoho paketu CAM z tohoto problemoveho souboru test_kapsch_consignia.pcap

Slozka pak obsahuje primo virtual environment pythonu kterym by vse melo jit spustit. Nicmene je zatim potreba pouze package asn1tools, json a pyshark (tedy i nainstalovany wireshark na PC)