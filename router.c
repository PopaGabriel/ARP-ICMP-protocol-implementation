#include <queue.h>
#include "skel.h"

struct arp_entry {
    __u32 ip;
    uint8_t mac[6];
};

typedef struct phisic_table
{
    struct arp_entry **vector;
    int size;
    int max_size;
}*ptable;

typedef struct entry
{
    u_int32_t prefix;
    u_int32_t next_hop;
    u_int32_t mask;
    int interface;
}*entry;

typedef struct table
{
    struct entry **vector;
    unsigned int size;
    unsigned int max_size;
}*entry_table;

ptable arp_table;
entry_table rtable;

entry get_best_route(__u32 dest_ip) {
    entry res = NULL;
    printf("Best route ip %d \n", dest_ip);
    for (int i = 0; i < rtable->size; i++) {
        if ((dest_ip & rtable->vector[i]->mask) == rtable->vector[i]->prefix) {
            if (res == NULL)
                res = rtable->vector[i];
            else if (ntohl(rtable->vector[i]->mask) > ntohl(res->mask))
                res = rtable->vector[i];
        }
    }
    if(res == NULL)
        printf("vezi ca turbeaza \n");
    return res;
}

struct arp_entry *get_arp_entry(__u32 ip) {
	int i;
	for (i = 0; i < arp_table->size; i++){
		if(arp_table->vector[i]->ip == ip)
			return arp_table->vector[i];
	}
    return NULL;
}

void add_entry_ptable(struct arp_entry *aux)
{
    if (aux == NULL)
        return;

    if (arp_table->max_size <= arp_table->size + 1)
        arp_table->vector = realloc(arp_table->vector, (arp_table->max_size + 100) * sizeof(struct arp_entry*));

    arp_table->vector[arp_table->size] = aux;
    arp_table->size ++;
}

ptable create_ptable()
{
    ptable aux = malloc(sizeof(struct phisic_table));
    aux->vector = malloc(100 * sizeof(struct arp_entry *));
    aux->size = 0;
    aux->max_size = 100;

    return aux;
}

entry_table create_table()
{
    entry_table aux = malloc(sizeof(struct table));
    aux->vector = (struct entry **)malloc(sizeof(struct entry *));
    aux->size =  0;
    aux->max_size = 0;
    return aux;
}

//Imi creez practic un nivel din tabela in format little endian
entry create_entry(char *prefix, char *next_hop, char *mask, int interface)
{
    entry aux = malloc(sizeof(struct entry));
	struct in_addr addr;

    aux->interface = interface;
    
	aux->prefix = inet_aton(prefix, &addr);
	aux->prefix = ntohl(addr.s_addr);
    
	aux->next_hop = inet_aton(next_hop, &addr);
	aux->next_hop = ntohl(addr.s_addr);
    
	aux->mask = inet_aton(mask, &addr);
	aux->mask = ntohl(addr.s_addr);

    printf("%d %d %d\n", aux->next_hop, aux->mask, aux->prefix);

    return aux;
}

void add_entry(entry_table table, entry Entry)
{
    if ((table==NULL) | (Entry == NULL))
        return;
    if (table->max_size <= table->size + 1) {
        table->vector = realloc(table->vector, (table->max_size + 1000)*sizeof(struct entry*));
        table->max_size += 1000;
    }
    table->vector[table->size] = Entry;
    table->size = table->size + 1;
    //printf("%ud %ud %ud %ud\n", table->vector[table->size-1]->prefix, table->vector[table->size-1]->next_hop, table->vector[table->size-1]->mask, table->vector[table->size-1]->interface);
}

void fill_components(char *buffer, char *prefix, char *next_hop, char *mask, char *interface)
{
    char *components;
    components = strtok(buffer, " ");
    strcpy(prefix, components);

    components = strtok(NULL, " ");
    strcpy(next_hop, components);

    components = strtok(NULL, " ");
    strcpy(mask, components);

    components = strtok(NULL, " ");
    strcpy(interface, components);
}

entry_table initiate_arg_table(char *filepath)
{
	FILE *f_input;
    f_input = fopen(filepath, "r");
    char buffer[100], component_mask[30], component_prefix[30], component_next_hop[30], interface[30];

    entry_table aux_table = create_table();

    while(fgets(buffer, 100, f_input)){
        fill_components(buffer, component_prefix, component_next_hop, component_mask, interface);
        add_entry(aux_table, create_entry(component_prefix, component_next_hop, component_mask, atoi(interface)));
    }
	return aux_table;
}

int main(int argc, char *argv[])
{
	packet m;
    queue queue_packets = queue_create();
	int rc;

	init(argc - 2, argv + 2);

	rtable = initiate_arg_table(argv[1]);
    arp_table = create_ptable();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

        struct ethhdr *eth_hdr = (struct ethhdr *)m.payload;
        struct ether_header *eth_header = (struct ether_header *)m.payload;
	    struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
        int verifica;
        //Verific ce tip de mesaj este
        
        if(ntohs(eth_hdr->h_proto) == ETH_P_ARP) {
            struct arp_header *arp_header = parse_arp(m.payload);
            if (ntohs(arp_header->op) == ARPOP_REQUEST ) {
                if (inet_addr(get_interface_ip(m.interface)) == arp_header->tpa) {
                    
                    //pregatesc mesajul
                    struct ethhdr *mesaj = malloc(sizeof(struct ethhdr));
                    get_interface_mac(m.interface, mesaj->h_source);
                    memcpy(mesaj->h_dest, eth_hdr->h_source, sizeof(eth_hdr->h_source));
                    mesaj->h_proto = htons(ETH_P_ARP);

                    //Trimit un mesaj de tip arp_reply
                    send_arp(arp_header->spa, inet_addr(get_interface_ip(m.interface)), (struct ether_header *)mesaj, m.interface, htons(ARPOP_REPLY));
                }
                continue;
            }
            if (ntohs(arp_header->op) == ARPOP_REPLY) {
                int auxiliar = 1;
                struct arp_entry *aux = malloc(sizeof(struct arp_entry));

                //Salvez adresa ip a sender-ului
                aux->ip = arp_header->spa;
                //Salvez adresa lui Mac
                memcpy(aux->mac, arp_header->sha, 6);
                //Adaug in arp_table
                add_entry_ptable(aux);

                while(!queue_empty(queue_packets)) {
                    verifica = 0;
                    auxiliar = 1;
                    packet *aux_packet = (packet *)queue_deq(queue_packets);
                    struct ether_header *eth_hdr_aux = (struct ether_header *)aux_packet->payload;
                    struct iphdr *ip_hdr_aux = (struct iphdr *)(aux_packet->payload + sizeof(struct ether_header));

                    entry best_entry_aux = get_best_route(ntohl(ip_hdr_aux->daddr));

                    //Verificare in caz ca a ajuns ceva pana aici cumva
                    if(best_entry_aux == NULL)
                        continue;

                    //Verific daca am adresa ip a destinatiei in arp_table
                    //Si daca am trimit packetul mai departe
                    for(int i = 0; i < arp_table->size; i++) {
                        if(arp_table->vector[i]->ip == htonl(best_entry_aux->next_hop) && auxiliar == 1) {
                            verifica = 1;
                            auxiliar = 0;
                            memcpy(eth_hdr_aux->ether_dhost, arp_table->vector[i]->mac, 6);
                            get_interface_mac(best_entry_aux->interface, eth_hdr_aux->ether_shost);
                            send_packet(best_entry_aux->interface, aux_packet);
                        }
                    }

                    // Daca nu-i am adresa in arp table
                    // il introduc in queue iar si ma opresc
                    if (verifica != 1) {
                        queue_enq(queue_packets, aux_packet);
                        break;
                    }              
                }
                continue;
            }
    } else {
        struct icmphdr * icmp_hdr = parse_icmp(m.payload);

        //Daca este destinat routerului
        if ((inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr)) {
            if (icmp_hdr->type == 8) {
                send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_header->ether_dhost, eth_header->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
            }
            continue;
        }

        if (ip_hdr->ttl <= 1) {
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_header->ether_dhost, eth_header->ether_shost, 11, 0, m.interface);
            continue;
        } 

        if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) 
            continue;

        entry best_entry = get_best_route(ntohl(ip_hdr->daddr));

        if (best_entry == NULL) {
            send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_header->ether_dhost, eth_header->ether_shost, 3, 0, m.interface);
            continue;
        }

        ip_hdr->ttl -= 1;
		ip_hdr->check = 0;
	    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

        struct arp_entry *best_arp_entry = get_arp_entry(ip_hdr->daddr);

        //Nu am gasit adresa mac a destinatie
        //Asa o sa salvez mesajul si dau o cerere ARP_Request ca sa o aflu
	    if (best_arp_entry == NULL) {
            packet *aux_packet = malloc(sizeof(packet));
            memcpy(aux_packet, &m, sizeof(packet));
            queue_enq(queue_packets, aux_packet);

            struct ether_header *aux_mesaj = malloc(sizeof(struct ether_header));
            
            //fac broadcast-ul
            for(int i=0; i<6; i++)
                aux_mesaj->ether_dhost[i] = 0xFF;
            get_interface_mac(best_entry->interface, aux_mesaj->ether_shost);
            aux_mesaj->ether_type = htons(ETH_P_ARP);

            send_arp(htonl(best_entry->next_hop), inet_addr(get_interface_ip(best_entry->interface)), aux_mesaj,  best_entry->interface, htons(ARPOP_REQUEST));
            
		    continue;
        }
        //Daca am deja adresa Mac atunci ii trimit packetul
        memcpy(eth_hdr->h_dest, best_arp_entry->mac, 6);
		get_interface_mac(best_entry->interface, eth_hdr->h_source);
		send_packet(best_entry->interface, &m);

        continue;
        }
    }
}
