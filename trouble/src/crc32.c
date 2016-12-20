#include "crc32.h"

#include <stdlib.h>
#include <sys/param.h>

uint32_t crc32_bitwise(const unsigned char* data, uint64_t length)
{
    uint32_t crc = ~0;
    const unsigned char* current = data;

    while (length-- != 0)
    {
        crc ^= *current++;

        for (int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (-(int32_t)(crc & 1) & 0xEDB88320);
        }
    }

    return ~crc;
}
