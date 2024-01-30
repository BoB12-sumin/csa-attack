#ifndef RADIOTAB_H
#define RADIOTAB_H

#include <sys/types.h>
#include "mac.h"

struct dot11
{
    u_int8_t it_version = 0; /* set to 0 */
    u_int8_t it_pad = 0;
    u_int16_t it_len = 8;     /* entire length */
    u_int32_t it_present = 0; /* fields present */
} __attribute__((__packed__));

#endif // RADIOTAB_H

#ifndef BEACON_H
#define BEACON_H

struct macpack
{
    Mac dmac;
    Mac smac;
};

#endif // BEACON_H