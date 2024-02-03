#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <wx/html/htmlwin.h>
#include <wx/textfile.h>
#include <wx/filedlg.h>
#include <wx/listctrl.h>

#include <mutex>
#include <thread>
#include <vector>

struct PacketInfo {
    wxString number;
    wxString timestamp;
    wxString sourceIP;
    wxString destIP;
    wxString length;
    wxString protocol;
    wxString data;
};
/*
class PacketHandler {
public:
    PacketHandler(MyPacketListCtrl* listCtrl) : packetListCtrl(listCtrl) {}
    void Start();
    void Stop();
    void ProcessPacket(const PacketInfo& packet);

private:
    void HandlePackets();
    void ProcessPacketsInternal(const std::vector<PacketInfo>& packets);
    

    MyPacketListCtrl* packetListCtrl;
    std::vector<PacketInfo> packetQueue;
    std::thread handlerThread;
    std::mutex mutex;
    std::condition_variable conditionVariable;
};
class MyPacketListCtrl : public wxListCtrl {
public:
    MyPacketListCtrl(wxWindow* parent) : wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
    void UpdateListCtrl(const std::vector<PacketInfo>& data);
    void AddDataToBuffer(const PacketInfo& newData);
    const std::vector<PacketInfo>& GetDataBuffer() const {
        return dataBuffer;
    }

private:
    std::vector<PacketInfo> dataBuffer;
};
*/

#endif