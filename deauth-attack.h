#pragma once

#include <cstdint>
#include <cstdio>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap_header
{
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_header
{
	uint8_t type;
	uint8_t flags;
	uint16_t duration;
	Mac daddr;
	Mac saddr;
	Mac bssid;
	uint16_t sequence;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_fixed
{
	uint16_t reason_code;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_packet
{
	radiotap_header rd_hdr;
	beacon_header bc_hdr;
	beacon_fixed bc_fxd;
};
#pragma pack(pop)
