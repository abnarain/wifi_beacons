#include "tcpdump.h"

#define MAC_TABLE_ENTRIES 255
typedef struct {
  char mac_add[18];
  char essid[48];
  int packet_count;
  int count_fcs;
  int count_short_preamble;
  float total_signal;
  float total_noise;
  float avg_rate; 
} address_table_entry_t;

typedef struct {
  /* A list of MAC mappings. A mapping ID is simply
   * that mapping's index offset into this array. */
  address_table_entry_t entries[MAC_TABLE_ENTRIES];
  /* The index of the first (i.e., oldest) mapping in the list */
  int first;
  /* The index of the last (i.e., newest) mapping in the list */
  int last;
  int length;
  /* The index of the last mapping sent to the server. */
  int added_since_last_update;
} address_table_t;

void address_table_init(address_table_t*  table);
int address_table_lookup(address_table_t*  table,struct r_packet* paket) ;
