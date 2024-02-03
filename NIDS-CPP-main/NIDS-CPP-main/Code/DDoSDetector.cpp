#include "DDoSDetector.h"

DDoSDetector::DDoSDetector() {
    // Constructor implementation (if needed)
}

bool DDoSDetector::detectDDoS(const std::string& srcIP) {
    auto currentTime = std::chrono::steady_clock::now();

    DDoSStats& stats = statsMap[srcIP]; // Reference to DDoSStats for the specific IP

    // Make sure lastPacketTime is initialized correctly somewhere in the code.
    if (stats.packetCount == 0 ||
        std::chrono::duration_cast<std::chrono::seconds>(currentTime - stats.lastPacketTime).count() > timeThresholdInSeconds) {
        stats.packetCount = 0;
        stats.lastPacketTime = currentTime;
    }

    stats.packetCount++;

    if (stats.packetCount > packetThreshold) {
        // DDoS detected.
        return true;
    }

    return false;
}
