#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

//Header sizes for display purposes 
#define ETHER_HEADERSIZE 14
#define ARP_HEADERSIZE 28
//Pre-Calculated TCP Header Offset 
#define TCPHDROFFSET(th)  (((th)->dataoffset & 0xf0) >> 4)
            
/*
    ===============================================================================
    Structures to parse the headers in the pcap files - Ethernet, IP, TCP and ARP
    ===============================================================================
*/

typedef struct ether 
{
    unsigned char desthost[6]; 
    unsigned char srchost[6];  
    unsigned short type;       // IP or ARP
}ether;

typedef struct IP 
{
    unsigned char headlen;    //Holds the version << 4 and the header length >> 2 
    unsigned char tos;        //Type of Service
    unsigned short totlen;     
    unsigned short ident;      
    unsigned short offset;    //Fragment Offset Field */
    unsigned char ttl;        //Time to Live */
    unsigned char protocol;   
    unsigned short ipchecksum;     
    struct in_addr sourceip;
    struct in_addr destip;     
}IP;
  
typedef struct TCP
{
    unsigned short srcport;   
    unsigned short destport;   
    uint32_t seqno;           
    uint32_t ackno;            
    unsigned char dataoffset;    
    unsigned char flags;
    unsigned short  window;     
    unsigned short  tcpchecksum;     
    unsigned short  urgptr;     
}TCP;


unsigned short getethertype(const unsigned char *);
void parser(char *);


int main(int argc, char *argv[])
{
    //File name is sent as an argument
    char *file = argv[1];
    
    //Display the menu and take the user's choice 
    parser(file);
    return 0;
} 

void parser(char *file)
{
    
    //Create a packet header and a data object
    struct pcap_pkthdr *header = NULL;
    const unsigned char *data = NULL;
    ether *ethernet = NULL;
    IP *ip = NULL;
    TCP *tcp = NULL;
    unsigned short sport = 0,dport = 0;
    unsigned long curtime = 0;
    
    //Variable Declarations
    int ipheadlen = 0;
    int val = 0;
    unsigned long count = 0;

    //Char array to hold the error. PCAP_ERRBUF_SIZE is defined as 256.
    char errbuff[PCAP_ERRBUF_SIZE];
 
    //Open the saved captured file and store result in pointer to pcap_t
    pcap_t *pcap = pcap_open_offline(file, errbuff);
 
    //Start reading packets one by one 
    while (1)
    {
	val = pcap_next_ex(pcap, &header, &data);
        if(val < 0) break;
        
        ethernet = (ether*)(data);
        if(ethernet->type == 8) // TCP/IP
        {
            curtime = header->ts.tv_sec;

            //Point to the IP header i.e. 14 bytes(Size of ethernet header) from the start 
            ip = (IP*)(data + ETHER_HEADERSIZE);
            ipheadlen = (ip->headlen & 0x0f)*4; 

            //Point to the TCP header as explained in IP
            tcp = (TCP*)(data + ETHER_HEADERSIZE + ipheadlen);
            sport = ntohs(tcp->srcport);
            dport = ntohs(tcp->destport);
            count++;
            printf("Epoch Time: %lu, srcport: %u, dstport: %u, count: %lu\n", curtime, sport, dport, count);
            
        }
    }
}
