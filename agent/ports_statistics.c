#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

//Header sizes for display purposes 
#define ETHER_HEADERSIZE 14
#define ARP_HEADERSIZE 28
#define LINEBUFFER 256

// Ports
#define PORT1 80
#define PORT2 443
#define PORT3 843
#define PORT4 8300

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


unsigned long parser(char *, FILE *, unsigned int);


int main(int argc, char *argv[])
{
    if(argc != 4) {
        printf("[%s]parameters missing (4)\n", __FILE__);
        return 1;
    }
    //File name is sent as an argument
    char *file = argv[1];
    char *wfile = argv[2];
    unsigned int period = atoi(argv[3]);
    FILE *wf = NULL;
    unsigned long ret = 1;

    if(file == NULL || wfile == NULL) {
        printf("[%s]main parameters error!\n", __FILE__);
        return ret;
    }
    wf = fopen(wfile, "w");
    if(wf == NULL) {
        printf("[%s]Open %s failed!\n", __FILE__, wfile);
        return ret;
    } else {
        ret = parser(file, wf, period);
        if(ret == 0) {
            printf("[%s] parser failed!\n", __FILE__);
            return ret;
        }
    }

    return ret;
} 

// return the END TIME
unsigned long parser(char *file, FILE* wf, unsigned int period)
{
    
    //Create a packet header and a data object
    struct pcap_pkthdr *header = NULL;
    const unsigned char *data = NULL;
    ether *ethernet = NULL;
    IP *ip = NULL;
    TCP *tcp = NULL;
    unsigned short sport = 0,dport = 0;
    unsigned long curtime = 0;
    unsigned long pretime = 0;

    //Variable Declarations
    int ipheadlen = 0;
    int val = 0;
    unsigned long count = 0;
    unsigned long counter[4] = {0};
    int len = 0;

    //Char array to hold the error. PCAP_ERRBUF_SIZE is defined as 256.
    char errbuff[PCAP_ERRBUF_SIZE] = {0};
    char wfbuffer[LINEBUFFER] = {0};

    if(wf == NULL || period < 0) {
        printf("[%s][%d]parameters error \n", __FILE__, __LINE__);
        return 0;
    }

    //Open the saved captured file and store result in pointer to pcap_t
    pcap_t *pcap = pcap_open_offline(file, errbuff);
 
    if(pcap == NULL) {
        printf("[%s]pcap_open_offline failed: %s\n", __FILE__, errbuff);
        return 0;
    }
    //Start reading packets one by one
    while(1) {
        val = pcap_next_ex(pcap, &header, &data);
        if(val < 0) {
                len = sprintf(wfbuffer, "%lu,%lu,%lu,%lu,%lu\n", pretime, counter[0], counter[1], counter[2], counter[3]);
                len = fwrite(wfbuffer, sizeof(char), len, wf);
                len = sprintf(wfbuffer,"\nEND_TIME,%lu\n", curtime);
                fwrite(wfbuffer, sizeof(char), len, wf);
            break;
        }

        curtime = header->ts.tv_sec;
        if(pretime == 0) {
            pretime = curtime;
            len = sprintf(wfbuffer,"START_TIME,%lu\nPORTS,%u,%u,%u,%u\nPERIOD,%u\n\n", pretime, PORT1, PORT2, PORT3, PORT4, period);
            fwrite(wfbuffer, sizeof(char), len, wf);
        }

        // IP
        sport = 0;
        dport = 0;
        ethernet = (ether*)(data);
        if(ethernet->type == 8) {
            //Point to the IP header i.e. 14 bytes(Size of ethernet header) from the start
            ip = (IP*)(data + ETHER_HEADERSIZE);
            // TCP
            if((unsigned int)(ip->protocol) == 6) {
                ipheadlen = (ip->headlen & 0x0f)*4;
                //Point to the TCP header as explained in IP
                tcp = (TCP*)(data + ETHER_HEADERSIZE + ipheadlen);
                sport = ntohs(tcp->srcport);
                dport = ntohs(tcp->destport);
            }
        }
        if(curtime >= pretime) {
            count = (curtime - pretime) / period;
        } else {
            continue;
        }
        while(1) {
            if(count == 0) {
                switch(sport){
                    case PORT1: counter[0]++; break;
                    case PORT2: counter[1]++; break;
                    case PORT3: counter[2]++; break;
                    case PORT4: counter[3]++; break;
                    default: {
                        switch(dport){
                            case PORT1: counter[0]++; break;
                            case PORT2: counter[1]++; break;
                            case PORT3: counter[2]++; break;
                            case PORT4: counter[3]++; break;
                            default: break;
                        }
                        break;
                    }
                }
                break;
            } else {
                len = sprintf(wfbuffer, "%lu,%lu,%lu,%lu,%lu\n", pretime, counter[0], counter[1], counter[2], counter[3]);
                if(len < 0) {
                    printf("sprintf error!\n");
                    return 0;
                }
                len = fwrite(wfbuffer, sizeof(char), len, wf);
                if(len < 0) {
                    printf("fwrite error!\n");
                    return 0;
                }
                memset(counter, 0, sizeof(counter));
                pretime = curtime;
                count--;
            }
        }

    }

    return curtime;
}
