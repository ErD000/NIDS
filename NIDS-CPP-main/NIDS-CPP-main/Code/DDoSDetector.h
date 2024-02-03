#ifndef DDOS_DETECTOR_H
#define DDOS_DETECTOR_H

#include <string>
#include <unordered_map>
#include <chrono>

// Structure to store statistics per IP address
struct DDoSStats {
    int packetCount;
    std::chrono::steady_clock::time_point lastPacketTime;
};

// DDoS Detector class definition
class DDoSDetector {
private:
    std::unordered_map<std::string, DDoSStats> statsMap;
    const int packetThreshold = 1000; // Detection threshold for DDoS.
    const int timeThresholdInSeconds = 1; // Time interval for the threshold.

public:
    // Constructor (if needed)
    DDoSDetector();

    // Method to detect DDoS
    bool detectDDoS(const std::string& srcIP);

    // Other methods and logic (if any)
};

#endif // DDOS_DETECTOR_H
