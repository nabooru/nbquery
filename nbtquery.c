

/*******************************************************************************
 * nbquery.c - Implementation of the RFC 1001/1002 Node Status Request.
 * This tool implements the NetBIOS API Adapter Status Query function.
 * Also known as Node Status Query and many other names, this NBT message is 
 * used to retrieve the NetBIOS name table for both the local computer and 
 * remote computers, and various statistics from LAN cards or virtual adapters.    
 * Modern systems ignore the data in the statistics record except for the first
 * six bytes (unit_id field), which are used to store the Ethernet MAC address.
 
 * gcc -o nbquery.exe nbquery.c -Wall -lw2_32
 *******************************************************************************/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* #pragma comment(lib, "Ws2_32.lib") */

typedef SOCKET socket_t;

#define NBT_DEFAULT_PORT 137    /* netbios-ns */
#define TIMEOUT_DEFAULT 5000

/* Packet header - 12 bytes */
struct nbstat_packet_header {
   uint16_t name_trn_id;
/* --- Flags field --- */
   /* 5-bit OPCODE field: */
   uint16_t r:       1; 
   uint16_t opcode:  4;
   /* 7-bit NM_FLAGS field: */
   uint16_t aa:      1;
   uint16_t tc:      1;
   uint16_t rd:      1;
   uint16_t ra:      1;
   uint16_t unused1: 1;
   uint16_t unused2: 1;
   uint16_t b:       1;
   /* 4-bit RCODE field: */
   uint16_t rcode:    4;
/* --- End of Flags field --- */
   uint16_t qdcount;
   uint16_t ancount;
   uint16_t nscount;
   uint16_t arcount;
};

/* Operation specifier */
#define OPCODE_QUERY        0x00
#define OPCODE_REGISTRATION 0x05
#define OPCODE_RELEASE      0x06
#define OPCODE_WACK         0x07
#define OPCODE_REFRESH      0x08

/* Question Section - 36 bytes */
struct nbstat_question_section {
   uint8_t   q_name[34];
   uint16_t  q_type;
   uint16_t  q_class;
};

#define QTYPE_NB     0x0020 /* Name Query */
#define QTYPE_NBSTAT 0x0021 /* Node status request */
#define QCLASS_IN    0x0001 /* Internet class */

/* Resource Record - 44 bytes */ 
struct nbstat_resource_record {
   uint8_t  rr_name[34];
   uint16_t rr_type;
   uint16_t rr_class;
   uint32_t ttl;
   uint16_t rdlength;
};

#define RR_TYPE_A      0x0001 /* IP address RR */
#define RR_TYPE_NS     0x0002 /* Name Server RR */
#define RR_TYPE_NULL   0x000A /* NULL RR */
#define RR_TYPE_NB     0x0020 /* General Name Service RR */
#define RR_TYPE_NBSTAT 0x0021 /* Node Status RR */
#define RR_CLASS_IN    0x0001 /* Internet class */

/* Node Entry - 18 bytes (RFC 1002, section 4.2.18) */
struct nbstat_node_name {
   uint8_t nbf_name[15]; /* NetBIOS format name */
   uint8_t suffix;       
   uint16_t g:        1; /* Group name flag */
   uint16_t ont:      2; /* Owner Node Type */
   uint16_t drg:      1; /* Deregistration flag */
   uint16_t cnf:      1; /* Conflict flag */
   uint16_t act:      1; /* Active name flag */  
   uint16_t prm:      1; /* Permanent name flag */
   uint16_t reserved: 9; /* Reserved, must be zero */
   struct nbstat_node_name *next;
};

/* Statistics field of the Node Status Response - 46 bytes */
struct nbstat_statistics {
   uint8_t  unit_id[6]; /* This is usually the hardware address (MAC). */
   uint8_t  jumpers;
   uint8_t  test_result;
   uint16_t version_number;
   uint16_t period_of_statistics;
   uint16_t number_of_crcs;
   uint16_t number_alignment_errors;
   uint16_t number_of_collisions;
   uint16_t number_send_aborts;
   uint32_t number_good_sends;
   uint32_t number_good_receives;
   uint16_t number_retransmits;
   uint16_t number_no_resource_conditions;
   uint16_t number_free_command_blocks;
   uint16_t total_number_command_blocks;
   uint16_t max_total_number_command_blocks;
   uint16_t number_pending_sessions;
   uint16_t max_number_pending_sessions;
   uint16_t max_total_sessions_possible;
   uint16_t session_data_packet_size;
};

/* Node Status Request */
struct nbstat_query {
    struct nbstat_packet_header hdr;
    struct nbstat_question_section question;
};

/* Node Status Response */
struct nbstat_response {
   struct nbstat_packet_header hdr;
   struct nbstat_resource_record rr;
   uint8_t num_names;
   struct nbstat_node_name *node;
   struct nbstat_statistics stat;  
};

/* Buffer object */
typedef struct buffer {
   void *data;
   size_t size;
   size_t length;
   /* size_t offset; */
} buffer_t;

/* nbtstat_t object */
typedef struct nbstat {
   struct sockaddr_in sin; 
   uint8_t hwaddr[6]; 
   int     count;  
   struct nbstat_node_name *node; /* Zero or more entries. */
} nbstat_t;

/* Error codes: */
#define NBSTAT_EOK      0x000
#define NBSTAT_ENOMEM   0x101
#define NBSTAT_EINVAL   0x102 
#define NBSTAT_EWSAFAIL 0x103
#define NBSTAT_ESOCKET  0x104
#define NBSTAT_EPROTO   0x105 /* Generic protocol error */
#define NBSTAT_ETRFLAG  0x106 /* Truncation flag in response. */
#define NBSTAT_ETIMEOUT 0x107
#define NBSTAT_EDEBUG   0x200


uint8_t dec8be(const void *p)
{
   uint8_t const *ptr = (uint8_t const *)p;

   return ptr[0];
}

uint16_t dec16be(const void *p)
{
   uint8_t const *ptr = (uint8_t const *)p;

   return ((ptr[0] << 8) | ptr[1]);
}

uint32_t dec32be(const void *p)
{
   uint8_t const *ptr = (uint8_t const *)p;

   return (((uint32_t)ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3]);
}

void enc8be(void *p, uint8_t x)
{
   uint8_t *ptr = (uint8_t *)p;

   ptr[0] = x;
}

void enc16be(void *p, uint16_t x)
{
   uint8_t *ptr = (uint8_t *)p;

   ptr[0] = (x >> 8) & 0xff;
   ptr[1] = x & 0xff;  
}

void enc32be(void *p, uint32_t x)
{
   uint8_t *ptr = (uint8_t *)p;

   ptr[0] = (x >> 24) & 0xff;
   ptr[1] = (x >> 16) & 0xff;
   ptr[2] = (x >>  8) & 0xff;
   ptr[3] = x & 0xff;
}

/* buffer_init */
static void buffer_init(buffer_t *buffer, void *data, size_t size)
{
   buffer->data = data;
   buffer->size = size;
   buffer->length = 0;   

   memset(buffer->data, 0x00, buffer->size);
}

/* winsock_init */
static int winsock_init(void)
{
   WORD wVersionRequested;
   WSADATA wsaData;
   int result;

   wVersionRequested = MAKEWORD(2, 2);
   result = WSAStartup(wVersionRequested, &wsaData);
   if (result != 0)
       return result;

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
       WSACleanup();
       return WSAVERNOTSUPPORTED;
   }

   return result;
}

/* socket_create - */
static int nbstat_socket(SOCKET *sfd, const char *target, uint16_t port, struct sockaddr_in *sin)
{
   struct addrinfo *result = NULL;
   struct addrinfo *ptr = NULL;
   struct addrinfo hints;
   char buffer[5+1];
   int rcode;
   int err = 0;

   /* Redundant, set flags, addrlen and canonname to NULL */
   memset(&hints, 0x00, sizeof(hints));
   
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_protocol = IPPROTO_UDP;
   hints.ai_flags = 4; /* AI_NUMERICHOST */


   _snprintf(buffer, sizeof(buffer), "%u", port);
   buffer[5] = '\0';

   rcode = getaddrinfo(target, buffer, &hints, &result);
   if (rcode != 0) {
       err = WSAGetLastError(); 
       WSACleanup();
       return err; 
   }

   *sfd = INVALID_SOCKET;

   for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

       *sfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
       if (*sfd == INVALID_SOCKET) {
           err = WSAGetLastError(); 
           WSACleanup();
           return err; 
       }
       rcode = connect(*sfd, ptr->ai_addr, (int)ptr->ai_addrlen); 
       if (rcode == SOCKET_ERROR) {
           closesocket(*sfd);
           *sfd = INVALID_SOCKET;
           continue;    
       }
       break;  
   }
  
   if (*sfd == INVALID_SOCKET) {
       err = WSAGetLastError();
       WSACleanup();
   } else 
       memcpy(sin, ptr->ai_addr, ptr->ai_addrlen);     
  
   freeaddrinfo(result);

   return err;
}

static int nbstat_send(socket_t sfd, buffer_t *buffer, const struct sockaddr_in *sin)
{
   char *ptr = buffer->data;
   size_t len = buffer->length;  
   
   return sendto(sfd, ptr, len, 0, (struct sockaddr *)sin, sizeof(*sin));
}

static int socket_timeout(socket_t sfd, fd_set *rdfdset, int delay)
{
   struct timeval timeout;

   FD_ZERO(rdfdset);
   FD_SET(sfd, rdfdset);
   timeout.tv_sec = delay / 1000;
   timeout.tv_usec = (delay % 1000) * 1000;

   return select(sfd+1, rdfdset, NULL, NULL, &timeout);
}

/* nbstat_recv */
static int nbstat_recv(socket_t sfd, buffer_t *buffer, struct sockaddr_in *sin)
{
   char *ptr = buffer->data;
   int sinlen = sizeof(*sin);
   int nr;

   nr = recvfrom(sfd, ptr, buffer->size, 0, (struct sockaddr *)sin, &sinlen); 
   if (nr == SOCKET_ERROR)
       return nr;

   buffer->length = nr;

   return nr;   
}

/* Encode the request */
static int nbstat_encode_request(buffer_t *buffer, const struct nbstat_query *query)
{
   uint8_t *ptr = NULL;
   uint16_t flags;

   if (buffer == NULL || query == NULL)
       return NBSTAT_EINVAL;

   ptr = buffer->data;

   enc16be(ptr, query->hdr.name_trn_id);
   ptr += sizeof(query->hdr.name_trn_id);   

   /* Encode flags. */
   flags = 0x0000;
   /* Opcode field: */
   flags |= (query->hdr.r << 15) & 0x8000;
   flags |= (query->hdr.opcode << 11) & 0x7800;
   /* NM Flags: */
   flags |= (query->hdr.aa << 10) & 0x0400;
   flags |= (query->hdr.tc <<  9) & 0x0200;
   flags |= (query->hdr.rd <<  8) & 0x0100;
   flags |= (query->hdr.ra <<  7) & 0x0080;
   flags |= (query->hdr.unused1 << 6) & 0x0040;
   flags |= (query->hdr.unused2 << 5) & 0x0020;
   flags |= (query->hdr.b << 4) & 0x0010;
   /* Result code of request: */
   flags |= query->hdr.rcode & 0x000f;

   enc16be(ptr, flags);
   ptr += sizeof(flags);

   enc16be(ptr, query->hdr.qdcount);
   ptr += sizeof(query->hdr.qdcount);
   enc16be(ptr, query->hdr.ancount);
   ptr += sizeof(query->hdr.ancount);
   enc16be(ptr, query->hdr.nscount);
   ptr += sizeof(query->hdr.nscount);
   enc16be(ptr, query->hdr.arcount);
   ptr += sizeof(query->hdr.arcount);

   memcpy(ptr, query->question.q_name, sizeof(query->question.q_name));
   ptr += sizeof(query->question.q_name);

   enc16be(ptr, query->question.q_type);
   ptr += sizeof(query->question.q_type);
   enc16be(ptr, query->question.q_class);
   ptr += sizeof(query->question.q_class);

   buffer->length = ptr - (uint8_t *)buffer->data;

   ptr = NULL;
   
   return NBSTAT_EOK; 
}

static void node_name_free(struct nbstat_node_name *node)
{
   struct nbstat_node_name *current = NULL, *tmp = NULL;

   if (node != NULL) {
       current = node;
       while (current != NULL) {
           tmp = current;
           current = current->next;
           free(tmp);   
       }
   }

}

/* Decode the response and validate */
static int nbstat_decode_response(buffer_t *buffer, struct nbstat_response *rep)
{
   struct nbstat_node_name *current = NULL, *tmp = NULL;
   uint8_t *ptr = NULL;
   uint16_t flags;
   size_t offset;
   int i; 

   /* Check whether the packet length does not exceed the maximum IP datagram size. */
   if (buffer->length > 576)
       return NBSTAT_EPROTO;

   ptr = buffer->data;
   rep->hdr.name_trn_id = dec16be(ptr);
   ptr += sizeof(rep->hdr.name_trn_id);

   flags = dec16be(ptr);
   ptr += sizeof(flags);

   /* Decode flags. Opcode field: */
   rep->hdr.r = (flags >> 15) & 0x1;
   rep->hdr.opcode = (flags >> 11) & 0xf;
   /* NM Flags: */
   rep->hdr.aa = flags;
   rep->hdr.tc = flags;
   rep->hdr.rd = flags;
   rep->hdr.ra = flags;
   rep->hdr.unused1 = flags;
   rep->hdr.unused2 = flags;
   rep->hdr.b = flags;
   rep->hdr.rcode = flags;

   rep->hdr.qdcount = dec16be(ptr);
   ptr += sizeof(rep->hdr.qdcount);
   rep->hdr.ancount = dec16be(ptr);
   ptr += sizeof(rep->hdr.ancount);
   rep->hdr.nscount = dec16be(ptr);
   ptr += sizeof(rep->hdr.nscount);
   rep->hdr.arcount = dec16be(ptr);
   ptr += sizeof(rep->hdr.arcount);

   /* Decode resource record. */
   ptr += sizeof(rep->rr.rr_name);
   rep->rr.rr_type = dec16be(ptr);
   ptr += sizeof(rep->rr.rr_type);

   if (rep->rr.rr_type != RR_TYPE_NBSTAT)
       return NBSTAT_EPROTO;    

   rep->rr.rr_class = dec16be(ptr);
   ptr += sizeof(rep->rr.rr_class);
   
   rep->rr.ttl = dec32be(ptr);
   ptr += sizeof(rep->rr.ttl);
   
   rep->rr.rdlength = dec16be(ptr);
   ptr += sizeof(rep->rr.rdlength);

   rep->num_names = dec8be(ptr);
   ptr += sizeof(rep->num_names);

   /* Make sure the remaining length is sensible. */
   offset = ptr - (uint8_t *)buffer->data;
   offset += 18 * rep->num_names + 46;
   
   if (offset != buffer->length)
       return NBSTAT_EPROTO;

   rep->node = NULL;

   /* Build the linked list. */
   for (i = 0; i < rep->num_names; i++) {

       current = malloc(sizeof(struct nbstat_node_name));
       if (current == NULL) {
           node_name_free(rep->node);
           return NBSTAT_ENOMEM; 
       }       

       current->next = NULL;

       if (rep->node == NULL)
           rep->node = current;
       else
           tmp->next = current;

       tmp = current;

       memcpy(current->nbf_name, ptr, sizeof(current->nbf_name));
       ptr += sizeof(current->nbf_name);

       current->suffix = dec8be(ptr);
       ptr += sizeof(current->suffix);
       
       flags = dec16be(ptr);
       /* Group Name Flag. If set, name is a GROUP. */
       current->g = (flags >> 15) & 0x1; 
       /* Owner Node Type (b00 = B; b01 = P; b10 = M; b11 = Reserved). */
       current->ont = (flags >> 13) & 0x3;
       /* Deregister Flag. If set, name is in the process of being deleted. */
       current->drg = (flags >> 12) & 0x1;
       /* Conflict Flag. If set, name on this node is in conflict. */
       current->cnf = (flags >> 11) & 0x1;
       /* Active Name Flag. All entries have this flag set. */
       current->act = (flags >> 10) & 0x1; /* $fixme */
       /* Permanent Name Flag. If set, entry is for permanent node name. */
       current->prm = (flags >> 9) & 0x1;
       /* Reserved, must be zero (0). */
       current->reserved = flags & 0x1ff; 

       ptr += sizeof(flags);           
          
   }

   for (i = 0; i < sizeof(rep->stat.unit_id); i++) {
       rep->stat.unit_id[i] = dec8be(ptr);
       ptr += sizeof(rep->stat.unit_id[i]); 
   }

   /* No modern implementation ever fills these fields. We decode them anyway. */
   rep->stat.jumpers = dec8be(ptr);
   ptr += sizeof(rep->stat.jumpers);
   rep->stat.test_result = dec8be(ptr);
   ptr += sizeof(rep->stat.test_result);
   rep->stat.version_number = dec16be(ptr);
   ptr += sizeof(rep->stat.version_number);
   rep->stat.period_of_statistics = dec16be(ptr);
   ptr += sizeof(rep->stat.period_of_statistics);
   rep->stat.number_of_crcs = dec16be(ptr);
   ptr += sizeof(rep->stat.number_of_crcs);
   rep->stat.number_alignment_errors = dec16be(ptr);
   ptr += sizeof(rep->stat.number_alignment_errors);
   rep->stat.number_of_collisions = dec16be(ptr);
   ptr += sizeof(rep->stat.number_of_collisions);
   rep->stat.number_send_aborts = dec16be(ptr);
   ptr += sizeof(rep->stat.number_send_aborts);
   rep->stat.number_good_sends = dec32be(ptr);
   ptr += sizeof(rep->stat.number_good_sends);
   rep->stat.number_good_receives = dec32be(ptr);
   ptr += sizeof(rep->stat.number_good_receives);
   rep->stat.number_retransmits = dec16be(ptr);
   ptr += sizeof(rep->stat.number_retransmits);
   rep->stat.number_no_resource_conditions = dec16be(ptr);
   ptr += sizeof(rep->stat.number_no_resource_conditions);
   rep->stat.number_free_command_blocks = dec16be(ptr);
   ptr += sizeof(rep->stat.number_free_command_blocks);
   rep->stat.total_number_command_blocks = dec16be(ptr);
   ptr += sizeof(rep->stat.total_number_command_blocks);
   rep->stat.max_total_number_command_blocks = dec16be(ptr);
   ptr += sizeof(rep->stat.max_total_number_command_blocks);
   rep->stat.number_pending_sessions = dec16be(ptr);
   ptr += sizeof(rep->stat.number_pending_sessions);
   rep->stat.max_number_pending_sessions = dec16be(ptr);
   ptr += sizeof(rep->stat.max_number_pending_sessions);
   rep->stat.max_total_sessions_possible = dec16be(ptr);
   ptr += sizeof(rep->stat.max_total_sessions_possible);
   rep->stat.session_data_packet_size = dec16be(ptr);
   ptr += sizeof(rep->stat.session_data_packet_size);

   offset = ptr - (uint8_t *)buffer->data;

   return offset != buffer->length ? NBSTAT_EDEBUG : NBSTAT_EOK; 
} 

/* netbios_encode_name */
static size_t netbios_encode_name(char *name, const char *src, uint8_t pad)
{
   char *ptr = name;
   int length = 16;
   int i;

   *ptr++ = 0x20;
   for (i = 0; i < length; i++) {
       *ptr++ = 0x41 + ((*src >> 4) & 0x0f);
       *ptr++ = 0x41 + (*src & 0x0f);
       src++;
   }
 
   *ptr = 0x00;
   return (size_t)(ptr - name);

}

void nbstat_free(nbstat_t *nbstat) 
{
   if (nbstat != NULL) {
       if (nbstat->node != NULL)
           node_name_free(nbstat->node);   
       free(nbstat);
   }
}

static int nbstat_close(socket_t sfd)
{
   int result;

   result = closesocket(sfd);
   WSACleanup();
  
   return result;
}

/* nbstat_query */
int nbstat_query(nbstat_t **nbstat, const char *target, uint16_t port, int timeout)
{
   SOCKET sfd = INVALID_SOCKET;
   struct sockaddr_in sin;
   struct nbstat_query query; /* Node status request */  
   struct nbstat_response rep; /* Node status response */
   struct nbstat_node_name *node;
   buffer_t buffer;
   char data[1024];
   char nbtname[16]; 
   fd_set rdfdset;
   int result;
   int i;
   int nready;
   
   result = winsock_init();
   if (result != 0)
       return NBSTAT_EWSAFAIL;

   result = nbstat_socket(&sfd, target, port, &sin);
   if (result != 0)
       return NBSTAT_ESOCKET; 

   query.hdr.name_trn_id = GetCurrentProcessId();

   query.hdr.r = 0;
   query.hdr.opcode = OPCODE_QUERY;
   query.hdr.aa = 0;
   query.hdr.tc = 0;
   query.hdr.rd = 0;
   query.hdr.ra = 0;
   query.hdr.unused1 = 0;
   query.hdr.unused2 = 0;
   query.hdr.b = 0;
   query.hdr.rcode = 0;
   
   query.hdr.qdcount = 1;
   query.hdr.ancount = 0;
   query.hdr.nscount = 0;
   query.hdr.arcount = 0;


   /* Encode the first-level NetBIOS name. */
   memset(nbtname, '\0', sizeof(nbtname));
   nbtname[0] = '*';
   netbios_encode_name((char *)query.question.q_name, nbtname, 0x20);

   query.question.q_type  = QTYPE_NBSTAT;
   query.question.q_class = QCLASS_IN;

   buffer_init(&buffer, data, sizeof(data));
   nbstat_encode_request(&buffer, &query);

   result = nbstat_send(sfd, &buffer, &sin);
   if (result == SOCKET_ERROR || result != buffer.length) {
       nbstat_close(sfd);
       return NBSTAT_EDEBUG;
   }
    
   buffer_init(&buffer, data, sizeof(data));
   
   if (timeout > 10000 || timeout <= 0)
       timeout = 3000;
     
   nready = socket_timeout(sfd, &rdfdset, timeout);
   if (nready == SOCKET_ERROR) {
       nbstat_close(sfd);    
       return NBSTAT_EDEBUG;
   } else if (nready == 0) {
       nbstat_close(sfd);
       return NBSTAT_ETIMEOUT;
   } else if (nready > 0) {
       if (FD_ISSET(sfd, &rdfdset)) { /* redundant*/
           result = nbstat_recv(sfd, &buffer, &sin);
           nbstat_close(sfd); 
           if (result == SOCKET_ERROR)
               return NBSTAT_EDEBUG; 
       }  
   } 
 
   /* Decode the response. */
   result = nbstat_decode_response(&buffer, &rep);
   if (result != NBSTAT_EOK)
       return result;

   *nbstat = (nbstat_t *)malloc(sizeof(nbstat_t));
   if (*nbstat == NULL) 
       return NBSTAT_ENOMEM;
     
   memset(*nbstat, 0x00, sizeof(nbstat_t));  
   (*nbstat)->sin = sin; 
   (*nbstat)->node = rep.node;
   node = (*nbstat)->node;

   while (node != NULL) {
       (*nbstat)->count++;       
       node = node->next; 
   }
         
   for (i = 0; i < sizeof((*nbstat)->hwaddr); i++)
       (*nbstat)->hwaddr[i] = rep.stat.unit_id[i];     

   return NBSTAT_EOK;
} 

struct error_list {
   int result;
   const char *str;
} error_list[] = {
  { NBSTAT_EOK,      "operation completed successfully" },
  { NBSTAT_ENOMEM,   "memory allocation failure" },
  { NBSTAT_EINVAL,   "an invalid argument was passed to a library function" },
  { NBSTAT_EWSAFAIL, "could not initialize the sockets layer" },
  { NBSTAT_ESOCKET,  "the system could not allocate a socket descriptor" },
  { NBSTAT_ETRFLAG,  "truncation flag was set in response" },
  { NBSTAT_ETIMEOUT, "request expired" }, 
  { NBSTAT_EDEBUG,   "debugging error" },
  { 0xffffffff,       NULL }
};

/* nbstat_error */
const char *nbstat_error(int x)
{
   /* static char buffer[128]; */
   const char *error = NULL;
   int i;
   
   for (i = 0; error_list[i].str != NULL; i++) {
      if (error_list[i].result == x) {
          error = error_list[i].str;   
          break; 
      }
   }
   if (error == NULL)
       error = "Unknown error";

   return error;
}


const char *netbios_service_name(uint8_t g, uint8_t suffix)
{
   const char *name = NULL;

   switch(suffix) {
       case 0x00: name = !g ? "Workstation Service" : "Browser Client"; break;
       case 0x01: name =  g ? "Master Browser" : NULL; break;
       case 0x1B: name = !g ? "Domain Master Browser" : NULL; break; 
       case 0x1D: name = !g ? "Master Browser" : NULL; break;
       case 0x1E: name =  g ? "Browser Service Elections" : NULL; break;
       case 0x20: name = !g ? "Default Name" : NULL; break;
       case 0x6A: break;
       case 0x6B: break;
       default:
           break;
   }
   if (name == NULL)
       name = "Unknown"; 
   
   return name;
}

/* nbstat_dump_nbtstat */
void nbstat_dump_nbtstat(const nbstat_t *nbstat)
{
   struct nbstat_node_name *current = NULL;
   const char *name;
   char ch;
   int i;

   putchar('\n');
   printf("    NetBIOS Remote Machine Table\n\n");
   printf("       Name             Type   Status     Description  \n");
   printf("    ----------------------------------------------\n");

   /* Traverse the linked list and print all the relevant info. */
   current = nbstat->node;

   while (current != NULL) {
       printf("    ");
       for (i = 0; i < 15; i++) {
           ch = current->nbf_name[i];     
           if (ch >= 0x20 && ch <= 0x79)
               putchar(ch);
           else
               putchar('.');
       }
       printf("<%02X> ", current->suffix);
       printf("%s ", !current->g ? "UNIQUE" : "GROUP "); /* Space in GROUP is for text alignment. */
       name = netbios_service_name(current->g, current->suffix);
       printf("Registered %s\n", name);

       current = current->next;
   }

   printf("\n    MAC Address = ");
   for (i = 0; i < sizeof(nbstat->hwaddr); i++) {
       if (i > 0) putchar('-');
       printf("%02X", nbstat->hwaddr[i]);    
   } 
   printf("\n");

}

/* To do: implement this function! */
void nbstat_dump_nmblookup(const nbstat_t *nbstat)
{
   printf("nmblookup-like output\n"); 
}

static int strtoi(char *str)
{
   return atoi(str);
}

int main(int argc, char *argv[])
{
   nbstat_t *nbstat = NULL;
   int port = 0;
   int timeout = 0;
   char *target = NULL;
   char *progname;
   int result;

   if (argc != 2 && argc != 4 && argc != 6) {
       fprintf(stderr, "-%s: incorrect number of arguments\n", argv[0]);
       fprintf(stderr, "\nUsage:   %s [-p port] [-t timeout] target\n", argv[0]);
       fprintf(stderr, "Example: %s -p 137 -t 3000 192.168.1.200\n", argv[0]); 
       return EXIT_FAILURE; 
   }

   progname = argv[0];
   argc--;
   argv++;

   while (argc > 1) {
       if (strcmp(*argv, "-p") == 0) {
           if (--argc < 1 || port != 0) {
               fprintf(stderr, "-%s: incorrect number of arguments for option -p\n", progname);
               return EXIT_FAILURE;
           }  
           port = strtoi(*(++argv));    
       } else if (strcmp(*argv, "-t") == 0) {
           if (--argc < 1 || timeout != 0) {
               fprintf(stderr, "-%s: incorrect number of arguments for option -t\n", progname);
               return EXIT_FAILURE; 
           }
           timeout = strtoi(*(++argv)); 
       } else {
           fprintf(stderr, "-%s: -unknown option %s \n", progname, *argv);
           return EXIT_FAILURE;
       }

       argc--; 
       argv++;  
   }

   target = *argv;
   
   if (port == 0) 
       port = 137; /* NBSTAT_DEFAULT_PORT; */
   if (timeout == 0) 
       timeout = 3000;

   result = nbstat_query(&nbstat, target, port, timeout);
   if (result != NBSTAT_EOK /*&& result != NBSTAT_ETIMEOUT*/ ) {
       printf("-%s: error! %s (0x%04X) \n", progname, nbstat_error(result), result);
       return EXIT_FAILURE;
   }

   nbstat_dump_nbtstat(nbstat);
   
   /* We are done, destroy the nbstat object! */
   nbstat_free(nbstat);

   return EXIT_SUCCESS;
}


/* EOF */
