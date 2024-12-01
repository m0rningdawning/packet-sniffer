#include <cstring>
#include <iomanip>
#include <iostream>
#include <pcap.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr,
                   const u_char *packet) {
    std::cout << "Packet captured! Length: " << pkthdr->len << " bytes\n";

    for (bpf_u_int32 i = 0; i < pkthdr->len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)packet[i];
        if ((i + 1) % 16 == 0)
            std::cout << '\n';
        else
            std::cout << ' ';
    }
    std::cout << "\n\n";
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *firstdev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Available devices:\n";
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << "- " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        else
            std::cout << " (No description available)";

        std::cout << "\n";
    }

    if (alldevs == nullptr) {
        std::cerr << "No devices found\n";
        return 1;
    }

    firstdev = alldevs;
    std::cout << "\nUsing device: " << firstdev->name

              << (firstdev->description ? firstdev->description
                                        : " (No description available)")
              << "\n";

    pcap_t *handle = pcap_open_live(firstdev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        std::cerr << "Error during packet capture: " << pcap_geterr(handle)
                  << "\n";
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
