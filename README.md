ForensicPCAP
============
ABOUT
============
ForensicPCAP is a Python Forensic tool to analyze a PCAP file.

DEPENDENCIES
============
ForensicPCAP uses Scapy and Cmd2. So first you have to install them typing :
```sh
apt-get install python-scapy
easy_install cmd2
```
HOW TO USE IT
============
ForensicPCAP uses Cmd2 so you can juste type "help" or "help &lt;command&gt;" to get informations.  &gt; can be used to write to a file. "shell" permits to exec shell commands.
##### Launch
```sh
python forensicPCAP file.pcap
```
##### Help
```sh
ForPCAP >>> help

Documented commands (type help <topic>):
========================================
_load           dstports  history  list   py    search     show   
_relative_load  ed        ipsrc    load   r     set        stat   
cmdenvironment  edit      l        mail   run   shell      version
dns             hi        li       pause  save  shortcuts  web    

Undocumented commands:
======================
EOF  eof  exit  help  q  quit
```
##### Stats
Prints stats about PCAP
```sh
ForPCAP >>> stat
## Calculating statistics about the PCAP ... OK.
## Statistics :
TCP : 142 packet(s)
UDP : 81 packet(s)
ICMP : 0 packet(s)
Other : 24 packet(s)
Total : 247 packet(s)
## End of statistics
```
##### Show
Prints information about packet or last command result.<br />Usage : 
- show : print result of the last command
- show &lt;packet id&gt; : show information about a specific packet

##### Dns
Prints all DNS requests from the PCAP file. The id before the DNS is the packet's id which can be use with the "show" command.
```sh
ForPCAP >>> dns
## Listing all DNS requests ...OK.
## Result : 34 DNS request(s)
ForPCAP >>> show
1 | www.url.com
2 | www.url2.com
```
### Dstports
Prints all destination ports from the PCAP file. The id before the DNS is the packet's id which can be use with the "show" command.
```sh
ForPCAP >>> dstports
## Listing all destination port in the PCAP ... OK.
Result : 20 ports##
ForPCAP >>> show
43 | 443
44 | 80
```
##### Ipsrc
Prints the number of ip source and store them.
```sh
ForPCAP >>> ipsrc
## Searching IP source ... .OK.
Result : 1 ips##
ForPCAP >>> show
10.0.0.1
```
##### Web
Prints the number of web's requests and store them
```sh
ForPCAP >>> web
## Searching web's request ... .................OK.

Web's request : 17
ForPCAP >>> show
GET / HTTP/1.1
Cache-Control: max-age = 1800
Connection: Keep-Alive
Accept: */*
User-Agent: 
Host: www.url.com
```

##### Mail
Prints the number of mail's requests and store them
```sh
ForPCAP >>> mail
## Searching mail's request ... OK.
Mail's request : 4
ForPCAP >>> show
+OK Dovecot ready.
CAPA
+OK
....
```

##### Search
Permits to search specific packets<br />
Usage :
```sh
- search <options>
        -p | --protocol <port number> (TCP by default) : this option must be the first option if changed
        --ip <ip>
        --dport | --destination-port <port number>
        --sport | --source_port <port number>
        --ipsrc | --ip-source <ip>
        --ipdst | --ip-destination <ip>
        -s | --string <string> : will search the string in all packets
        ```
 Example :
```sh
ForPCAP >>> search --dport 80
## Searching request ... ..............................................................................................................
Search's result : 1
ForPCAP >>> show
1 | Ether / IP / TCP 10.0.0.1:49173 > 192.168.0.1:http S
```
Contact
============
You can contact me at cloud(at)madpowah(dot)org
