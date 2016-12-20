#include <stdint.h>

// based on http://create.stephan-brumme.com/crc32/#git1
uint32_t crc32_bitwise(const unsigned char* data, uint64_t length);
