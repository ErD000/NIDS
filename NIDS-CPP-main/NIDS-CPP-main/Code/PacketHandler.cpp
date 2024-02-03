#include "PacketHandler.h"
/*
//Packet Handler
void PacketHandler::Start() {
    handlerThread = std::thread([this]() {
        HandlePackets();
        });
}
void PacketHandler::Stop() {
    if (handlerThread.joinable()) {
        handlerThread.join();
    }
}

// Function to be called by the PCAP thread to process packets
void PacketHandler::ProcessPacket(const PacketInfo& packet) {
    std::unique_lock<std::mutex> lock(mutex);
    packetQueue.push_back(packet);
    lock.unlock();
    conditionVariable.notify_one();
}
void PacketHandler::HandlePackets() {
    while (true) {
        std::unique_lock<std::mutex> lock(mutex);
        conditionVariable.wait(lock, [this]() {
            return !packetQueue.empty();
            });

        // Process all packets in the queue
        std::vector<PacketInfo> packetsToProcess = std::move(packetQueue);
        packetQueue.clear();

        lock.unlock();

        // Process packets
        ProcessPacketsInternal(packetsToProcess);
    }
}
void PacketHandler::ProcessPacketsInternal(const std::vector<PacketInfo>& packets) {
    // Process packets and update UI
    for (const auto& packet : packets) {
        packetListCtrl->AddDataToBuffer(packet);
    }

    // Trigger UI update
    wxQueueEvent(packetListCtrl, new wxThreadEvent());
}

//PacketListCtrl
MyPacketListCtrl::MyPacketListCtrl(wxWindow* parent) : wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT) {
    InsertColumn(0, wxT("Number"), wxLIST_FORMAT_LEFT, 60);
    InsertColumn(1, wxT("Timestamp"), wxLIST_FORMAT_LEFT, 120);
    InsertColumn(2, wxT("Source IP"), wxLIST_FORMAT_LEFT, 85);
    InsertColumn(3, wxT("Destination IP"), wxLIST_FORMAT_LEFT, 85);
    InsertColumn(4, wxT("Length"), wxLIST_FORMAT_LEFT, 70);
    InsertColumn(5, wxT("Protocol"), wxLIST_FORMAT_LEFT, 60);
    InsertColumn(6, wxT("Data"), wxLIST_FORMAT_LEFT, 400);
}
// Function to update the list control with data
void MyPacketListCtrl::UpdateListCtrl(const std::vector<PacketInfo>& data) {
    // Update list control implementation here
    // ...
    // Clear the buffer after updating the list control
    dataBuffer.clear();
}
// Function to add incoming data to the buffer
void MyPacketListCtrl::AddDataToBuffer(const PacketInfo& newData) {
    dataBuffer.push_back(newData);
}
// Function to get the buffer data (if needed)
*/