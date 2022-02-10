#include <queue.h>
#include <unistd.h>
#include <fcntl.h> 
#include <errno.h> 
#include <stdio.h>
#include "skel.h"
#define NMAX 100
#define DIMAX 70000

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

int read_rtable(struct route_table_entry *rtable);

struct route_table_entry *rtable;
int root_table_size;

struct arp_entry *arp_table;
int arp_table_len;

typedef struct tabela {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} tabel;

tabel *tabel_root;

void parse_arp_table() 
{
    FILE *f;
    //fprintf(stderr, "Parsing ARP table\n");
    f = fopen("arp_table.txt", "r");
    DIE(f == NULL, "Failed to open arp_table.txt");
    char line[100];
    int i = 0;
    for(i = 0; fgets(line, sizeof(line), f); i++) {
        char ip_str[50], mac_str[50];
        sscanf(line, "%s %s", ip_str, mac_str);
        //fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
        arp_table[i].ip = inet_addr(ip_str);
        int rc = hwaddr_aton(mac_str, arp_table[i].mac);
        DIE(rc < 0, "invalid MAC");
    }
    arp_table_len = i;
    fclose(f);
    //fprintf(stderr, "Done parsing ARP table.\n");
}

	tabel *get_best_route(__u32 dest_ip) {
	/* TODO 1: Implement the function */
	int i;
	tabel *cur_best_entry = NULL;
	for (i = 0; i < root_table_size; i++){
		if(cur_best_entry == NULL){
			if((tabel_root[i].mask & dest_ip) == tabel_root[i].prefix){
				cur_best_entry = &tabel_root[i];
			}
		}
		else{
			if((tabel_root[i].mask & dest_ip) == tabel_root[i].prefix){
				if(tabel_root[i].mask > cur_best_entry->mask){
					cur_best_entry = &tabel_root[i];
				}
			}
		}
	}
	return cur_best_entry;
}

/*
 Returns a pointer (eg. &arp_table[i]) to the best matching ARP entry.
 for the given dest_ip or NULL if there is no matching entry.
*/
struct arp_entry *get_arp_entry(__u32 ip) {
    /* TODO 2: Implement */
	int i;
	for (i = 0; i < arp_table_len; i++){
		if(arp_table[i].ip == ip)
			return &arp_table[i];
	}
    return NULL;
}


void fatal(char * mesaj_eroare)
{
    perror(mesaj_eroare);
    exit(0);
}

int main(int argc, char *argv[])
{
	packet m;
	arp_table = malloc(sizeof(struct  arp_entry) * 100);
    parse_arp_table();
	FILE *file;
	tabel_root = (tabel *) malloc(sizeof(tabel) * DIMAX);
	int rc, n = 0, i, j;
	char buf[NMAX];
	char *token;
	int nr = 0;

	printf("DAAAAAA");

	 init(argc - 2, argv + 2);

	file = fopen(argv[1], "r");

	if(file == NULL) {
		fatal("nu s-a putut deschide fisierul");
		return -1;
	}

	while( fgets(buf, NMAX, file) != NULL) {
		token = strtok(buf, " ");
		nr = 1;
		while( token != NULL ) {
			//puts(token);
			if(nr == 1)	
				tabel_root[n].prefix = inet_addr(token);
			if(nr == 2)	
				tabel_root[n].next_hop = inet_addr(token);
			if(nr == 3)	
				tabel_root[n].mask = inet_addr(token);
			if(nr == 4)	
				tabel_root[n].interface = atoi(token);
			nr++;
		 	token = strtok(NULL, " ");
   		}
		   //printf("%d %d %d %d\n", tabel_root[i].prefix, tabel_root[i].next_hop, tabel_root[i].mask , tabel_root[i].interface);
		token = NULL;
		n++;
	}
	root_table_size = n;

	fclose(file);

	// for(j = 0; j< n; j++) {
	// 	printf("%d %d %d %d\n", tabel_root[j].prefix, tabel_root[j].next_hop, tabel_root[j].mask , tabel_root[j].interface);
	// 	uint8_t octet[4];

    //     for ( i=0; i<4; i++)
    //     {
    //         octet[i] = ( tabel_root[j].prefix >> (i*8) ) & (uint8_t)-1;
    //     }
    //     printf("%d.%d.%d.%d\n", octet[0], octet[1], octet[2],octet[3]);
	// }

	

	while (1) {
		rc = get_packet(&m);
		int flag = 0;
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = parse_icmp(m.payload);


		for(int j = 0; j < ROUTER_NUM_INTERFACES; j++) 
			if(inet_addr(get_interface_ip(j)) == ip_hdr->daddr) {
				flag = 1;
				break;
			}


		printf("%d \n", flag);
		//printf("%d \n", icmp_hdr->type);
		if (flag == 1) {
			if(icmp_hdr != NULL) {
				if (icmp_hdr->type == 8) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
					printf("salalam\n");
					continue;
				}
			}
		}

		if(ip_hdr->ttl <= 1){
			printf("1\n");
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
			continue;
		}

		if(ip_checksum(ip_hdr,sizeof(struct iphdr))){
			printf("2\n");
			continue;
		}

		ip_hdr->ttl -= 1;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		tabel *best_entry = get_best_route(ip_hdr->daddr);

		if( best_entry == NULL) {
			printf("3\n");
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0, m.interface);
			continue;
		}



		struct arp_entry *best_arp_entry = get_arp_entry(ip_hdr->daddr);

		if(best_arp_entry == NULL) {
			printf("4\n");
			continue;
		}


		for (i = 0; i < 6; i++) {
			(eth_hdr->ether_dhost)[i] = (best_arp_entry->mac)[i];
		}


		printf("5\n");
		if(best_entry == NULL)
			printf("daaa e null");

		printf("%d %d %d %d\n", best_entry->prefix, best_entry->next_hop, best_entry->mask , best_entry->interface);

		get_interface_mac(best_entry->interface, eth_hdr->ether_shost);
		
		printf("6\n");

		send_packet(best_entry->interface, &m);
		/* Students will write code here */

	}
}