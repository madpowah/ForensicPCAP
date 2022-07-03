#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  forensicPCAP.py
#  


from cmd2 import Cmd
from optparse import OptionParser
from scapy.all import *
import sys
import re

class bcolors:
    HEADER = '\033[95m'
    PROMPT = '\033[94m'
    TXT = '\033[93m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    
class ForensicPCAP(Cmd):
	
	
############# __init() ###########
	def __init__(self, namefile):
		Cmd.__init__(self)
		self.last = []
		self.last.append([])
		self.prompt = bcolors.PROMPT + "ForPCAP >>> " + bcolors.ENDC
		self.loadPcap(namefile)
		self.cmd = ""

############# loadPcap() ###########
	def loadPcap(self, namefile):
		sys.stdout.write(bcolors.TXT + "## Loading PCAP " + namefile + " ... ")
		sys.stdout.flush()
		self.pcap = rdpcap(namefile)
		sys.stdout.write("OK." + bcolors.ENDC + "\n")
		self.last = self.pcap
		
############# do_version() ###########	
	def do_version(self, arg, opts=None):
		"""Print version of forensicPCAP
Usage :
- version"""
		print(bcolors.TXT + "ForensicPCAP v0.3 written by cloud@madpowah.org")

############# do_dns() ###########
	def do_dns(self, arg, opts=None):
		"""Print all DNS requests in the PCAP file
Usage :
- dns"""
		sys.stdout.write(bcolors.TXT + "## Listing all DNS requests ...")
		sys.stdout.flush()
		dns = []
		dns.append([])
		
		for i,packet in enumerate(self.pcap):
			if DNS in packet:
				res = packet.getlayer('DNS').qd.qname
				if res[len(res) - 1] == '.':
					res = res[:-1]
				dns.append([i, res])

		sys.stdout.write("OK.\n")
		print(bcolors.TXT + "## Result : " + str(len(dns) - 1) + " DNS request(s)" + bcolors.ENDC)
		self.last = dns
		self.cmd = "dns"
		
############# do_dstports() ###########
	def do_dstports(self, arg, opts=None): 
		"""Print all destination ports in the PCAP file
Usage :
- dstports"""
		sys.stdout.write(bcolors.TXT + "## Listing all destination port in the PCAP ... ")
		sys.stdout.flush()
		ports = []
		ports.append([])
		for i,packet in enumerate(self.pcap):
			if TCP in packet: 
				res = packet.getlayer('TCP').dport
				test = 0
				for port in ports:
					if len(port) == 2:
						if int(res) == int(port[1]):
							test = 1
							break
				if test == 0:
					ports.append([i, res])
		sys.stdout.write("OK.\n")
		print(bcolors.TXT + "Result : " + str(len(ports) - 1) + " ports##" + bcolors.ENDC)
		self.last = ports
		self.cmd = "dstports"

############# do_stat() ###########
	def do_stat(self, arg, opts=None):
		"""Print stats about PCAP
Usage : 
- stat"""
		sys.stdout.write(bcolors.TXT + "## Calculating statistics about the PCAP ... ")
		sys.stdout.flush()
		tcp = 0
		udp = 0
		arp = 0
		icmp = 0
		other = 0
		for packet in self.pcap:
			if TCP in packet:
				tcp = tcp + 1
			elif UDP in packet:
				udp = udp + 1
			elif ARP in packet:
				arp = arp + 1
			elif ICMP in packet:
				icmp = icmp + 1
			else:
				other = other + 1
		sys.stdout.write("OK.\n"+ bcolors.ENDC)
		print("## Statistics :")
		print("TCP : " + str(tcp) + " packet(s)")
		print("UDP : " + str(udp) + " packet(s)")
		print("ARP : " + str(arp) + " packet(s)")
		print("ICMP : " + str(icmp) + " packet(s)")
		print("Other : " + str(other) + " packet(s)")
		print("Total : " + str(tcp + udp + arp + icmp + other) + " packet(s)")
		print("## End of statistics")
		
		self.cmd = "stat"
		
############# do_mail() ###########		
	def do_mail(self, arg, opts=None):
		"""Print the number of mail's requests and store its
Usage :
- mail"""
		sys.stdout.write(bcolors.TXT + "## Searching mail's request ... ")
		sys.stdout.flush()
		con = []
		mailpkts = []
		for i,packet in enumerate(self.pcap):
			if TCP in packet:
				if packet.getlayer('TCP').dport == 110 or packet.getlayer('TCP').sport == 110 or packet.getlayer('TCP').dport == 143 or packet.getlayer('TCP').sport == 143 :
					if packet.getlayer('TCP').flags == 2:
						con.append(i)
					mailpkts.append(packet)
		sys.stdout.write("OK.\n")
		print("## Result : Mail's request : " + str(len(con)))
		sys.stdout.write(bcolors.TXT + "## Saving mails ... ")
		sys.stdout.flush()
		res = ""
		for packet in mailpkts:
				if packet.getlayer('TCP').flags == 24:
					res = res + packet.getlayer('Raw').load
					sys.stdout.write(".")
					sys.stdout.flush()
		sys.stdout.write("OK\n")
		sys.stdout.flush()			
		self.cmd = "mail"			
		self.last = res
		
############# do_ipsrc() ###########		
	def do_ipsrc(self, arg, opts=None):
		"""Print the number of ip source and store its
Usage :
- ipsrc"""
		sys.stdout.write(bcolors.TXT + "## Searching IP source ... ")
		sys.stdout.flush()
		ips = []
		for packet in self.pcap:
			if TCP in packet:
				if packet.getlayer('TCP').flags == 2:
					res = packet.getlayer('IP').src
					test = 0
					for ip in ips:
						if str(res) == str(ip):
							test = 1
							break
					if test == 0:
						ips.append(res)
						sys.stdout.write(".")
						sys.stdout.flush()
		sys.stdout.write("OK.\n")
		print(bcolors.TXT + "Result : " + str(len(ips)) + " ips##" + bcolors.ENDC)
		self.cmd = "ipsrc"
		self.last = ips
		
############# do_web() ###########
	def do_web(self, arg, opts=None):
		"""Print the number of web's requests and store its
Usage :
- web"""
		sys.stdout.write(bcolors.TXT + "## Searching web's request ... ")
		sys.stdout.flush()
		con = []
		webpkts = []
		for i,packet in enumerate(self.pcap):
			if TCP in packet:
				if packet.getlayer('TCP').dport == 80:
					if packet.getlayer('TCP').flags == 2:
						con.append(i)
						sys.stdout.write(".")
						sys.stdout.flush()
					webpkts.append(packet)
		sys.stdout.write("OK.\n")
		print("\nWeb's request : " + str(len(con)) + bcolors.ENDC)
		
		res = ""
		for packet in webpkts:
				if packet.getlayer('TCP').flags == 24:
					res = res + str(packet.getlayer('Raw').load)
					
		self.cmd = "web"			
		self.last = res

############# do_followTCPStream() ###########
	def do_followtcpstream(self, arg, opts=None):
		"""Follow TCP sequence
Usage :
- followtcpstream <packet ID>"""
		sys.stdout.write(bcolors.TXT + "## Searching TCP Stream in PCAP ... ")
		sys.stdout.flush()
		l = self.pcap[int(arg)]
		ipsrc = l.getlayer("IP").src
		ipdst = l.getlayer("IP").dst
		portsrc = l.getlayer("TCP").sport
		portdst = l.getlayer("TCP").dport
		
		pkt = []
		pkt.append([])
		for i,p in enumerate(self.pcap):
			if p.haslayer('TCP'):
				if p[IP].src == ipsrc and p[IP].dst == ipdst and p[TCP].sport == portsrc and p[TCP].dport == portdst:
					pkt.append([i, p])
				if p[IP].src == ipdst and p[IP].dst == ipsrc and p[TCP].sport == portdst and p[TCP].dport == portsrc:
					pkt.append([i, p])
					
		sys.stdout.write("OK\n" + bcolors.ENDC)
		self.cmd = "followTCPStream"
		self.last = pkt

		
############# do_search() ###########
	def do_search(self, arg, opts=None):
		"""Search spécifics packets
Usage :
- search <options>
	-p | --protocol <port number> (TCP by default) : this option must be the first option if changed
	--ip <ip>
	--dport | --destination-port <port number>
	--sport | --source_port <port number>
	--ipsrc | --ip-source <ip>
	--ipdst | --ip-destination <ip>
	-s | --string <string> : will search the string in all packets"""		
		
		pkts = []
		pkts.append([])
		search = arg.split(' ')
		parser = OptionParser()
		parser.add_option("-p", "--protocol", dest="protocol", default="TCP", type="string",
                  help="filtering by protocol", )
		parser.add_option("--dport", "--destination-port", dest="dport", type="int",
                  help="filtering by destination port")
		parser.add_option("--sport", "--source-port", dest="sport", type="int",
                  help="filtering by source port")
		parser.add_option("--ipsrc", "--ip-source", dest="ipsrc", type="string",
                  help="filtering by ip source")
		parser.add_option("--ipdst", "--ip-destination", dest="ipdst", type="string",
                  help="filtering by ip destination")
		parser.add_option("-s", "--string", dest="stringdata", type="string",
                  help="filtering by string")
		(options, args) = parser.parse_args(args=search)
		searchstring = ""
		nb = 1
		
		## Create the request
		if options.protocol != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + '(packet.getlayer(\'' + options.protocol + '\') != None)'
			nb = nb + 1
		if options.dport != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + '(packet.getlayer(\'' + options.protocol + '\').dport == ' + str(options.dport) + ')'
			nb = nb + 1
		if options.sport != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + '(packet.getlayer(\'' + options.protocol + '\').sport == ' + str(options.sport) + ')'
			nb = nb + 1
		if options.ipsrc != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + '(packet.getlayer(\'IP\').src == "' + str(options.ipsrc) + '")'
			nb = nb + 1
		if options.ipdst != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + '(packet.getlayer(\'IP\').dst == "' + str(options.ipdst) + '")'
			nb = nb + 1
		if options.stringdata != None:
			if nb > 1:
				searchstring = searchstring + ' and '
			searchstring = searchstring + ' re.search("' + str(options.stringdata) + '" ,packet.getlayer(\'Raw\').load )'
			nb = nb + 1

		sys.stdout.write(bcolors.TXT + "## Searching request ... ")
		sys.stdout.flush()
		for i,packet in enumerate(self.pcap):
			try:
				## Dirty but working
				if eval(searchstring):
						pkts.append([i,packet])
						sys.stdout.write(".")
						sys.stdout.flush()
			except:
				error = ''
				
		print("\nSearch's result : " + str(len(pkts) - 1))			
		self.cmd = "search"			
		self.last = pkts
				

		
############# do_show() ###########				
	def do_show(self, arg, opts=None):
		"""Print information about packet or last command result
Usage : 
- show : print result of the last command
- show <packet id> : show information about a specific packet
- show raw : show the raw data if last command was followtcpstream
- show pcap : show all a summary of all packets"""
		args = arg.split(' ')
		if len(arg) < 1:
			if self.pcap != self.last:
				for var in self.last:
					if self.cmd == 'ipsrc':
						print(var)
					elif (len(var)) == 2:
						if self.cmd == "search" or self.cmd == "followTCPStream":
							print((str(var[0]) + " | " + str(self.pcap[int(var[0])].summary())))
						else:
							print((str(var[0]) + " | " + str(var[1])))
					elif (len(var)) == 1:
						sys.stdout.write(str(var))
			else:
				self.last.show()

		elif len(args) == 1:
				if args[0] == "raw":
					for p in self.last:
						if len(p) > 0:
							if self.pcap[int(p[0])].getlayer('Raw'):
								print(str(self.pcap[int(p[0])].getlayer('Raw').load))
								
				if args[0] == "pcap":
					for i,p in enumerate(self.pcap):
						print(str(i) + " | " + str(p.summary()))
				else: #Print packet detail
					self.pcap[int(arg)].show()		
			
 ############# main() ###########  
def main():
	
	shell = ForensicPCAP(sys.argv[1])
	shell.cmdloop()

if __name__ == '__main__':
	main()

