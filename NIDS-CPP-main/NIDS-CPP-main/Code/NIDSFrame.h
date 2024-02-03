#ifndef NIDS_FRAME_H
#define NIDS_FRAME_H


#include "CustomEvents.h"

#include <wx/wx.h>
#include <wx/listctrl.h>
#include <wx/html/htmlwin.h>
#include <wx/textfile.h>
#include <wx/filedlg.h>
#include <wx/listctrl.h>

#include <pcap.h>
#include <thread>
#include <vector>
#include <array>
#include <chrono>

using TimeStamp = std::chrono::time_point<std::chrono::system_clock>;
struct NmapBuffer {
    std::array<uint8_t, 4> IPV4;
    int OpeningRequest = 0;
    TimeStamp Delay;
};

//Structure to store packet info
struct PacketStruct {
    uint16_t IP_Type = 0;
    uint8_t IHL = 0;
    uint8_t Data_Offset = 0;
    uint8_t Protocol = 0;
    std::array<uint8_t, 4> IPV4_Source;
    std::array<uint8_t, 4> IPV4_Destination;
    std::array<uint8_t, 16> IPV6_Source;
    std::array<uint8_t, 16> IPV6_Destination;
    std::array<uint8_t, 6> MAC_Source;
    std::array<uint8_t, 6> MAC_Destination;
    uint16_t port_Source = 0;
    uint16_t port_Destination = 0;
    uint16_t packetSize = 0;
    uint16_t dataSize = 0;
    uint32_t sequenceNumber = 0;
    uint32_t ACK = 0;
    uint8_t Flags = 0;
    uint16_t Window_Size = 0; // Named: Lenght in UDP
    uint16_t Checksum = 0;

    long tv_sec = 0;
    long tv_usec = 0;

    //Variable information
    std::vector<uint8_t> Protocol_Option;
    std::vector<uint8_t> Payload;
};

//Declare NidsFrame function ...
class NIDSFrame : public wxFrame {
public:
    NIDSFrame(const wxString& title, const wxPoint& pos, const wxSize& size);
    void OnTextAppend(wxCommandEvent& event);
    std::vector<wxString> alertMessages; // Stocke les messages d'alerte

private:
    pcap_t* handle; // D�clarer le handle de capture
    wxListCtrl* m_packetListCtrl;
    wxListCtrl* m_alertListControl;
    bool checkForNmapScan(const u_char* packet, unsigned int length);
    bool checkForDDoS(const wxString& srcIP);
    void processAlert(const wxString& alertMessage);
    void OnStartCapture(wxCommandEvent& event);
    void OnStopCapture(wxCommandEvent& event);
    void OnAddDetectionRule(wxCommandEvent& event);
    void OnShowAlerts(wxCommandEvent& event);
    void OnClearDisplay(wxCommandEvent& event);
    void OnSaveLogs(wxCommandEvent& event);
    void OnSaveAlerts(wxCommandEvent& event);
    void RuleFrameLoader(wxCommandEvent& event);
    void wxWidgetChartDrawer();
    void packetScanner_NMAP();
    void alertTester(wxCommandEvent& event);

    static void packetHandlerWrapper(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet); // Supprimer 'NIDSFrame* frame' des param�tres
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnOpenDocumentation(wxCommandEvent& event);


    wxButton* m_startButton;
    wxButton* m_stopButton;
    //wxButton* m_addRuleButton;
    wxButton* m_clearDisplayButton;
    wxButton* m_saveLogsButton;
    wxButton* m_saveAlertsButton;
    wxButton* m_testAlert;
    // wxButton* m_loadRulesButton;
    wxButton* m_ruleFrameLoader;
    wxChoice* m_interfaceChoice;
    wxTextCtrl* m_packetDisplay;

    wxStaticText* m_statusLabel;
    wxGauge* m_packetCounter;

    std::vector<PacketStruct> PacketStructVector;
  

    
    int LocationAlertTest = 0;
    int packetCounter = 0;
    bool stopCaptureFlag;
    std::thread captureThread;
    std::thread chartDrawerThread;
    std::thread packetScannerThread_NMAP;
    std::thread packetScannerThread_RULES;
    ~NIDSFrame();

    wxDECLARE_EVENT_TABLE();
};
//Shortcut to add a buton with a style
class StyledButton : public wxButton {
public:
    StyledButton(wxWindow* parent, int id, const wxString& label,
        const wxPoint& pos, const wxSize& size,
        const wxColour& bg_color, const wxColour& fg_color,
        const wxFont& font)
        : wxButton(parent, id, label, pos, size)
    {
        SetBackgroundColour(bg_color);
        SetForegroundColour(fg_color);
        SetFont(font);
    }
};
//Documentation Frame
class DocumentationFrame : public wxFrame {
public:
    DocumentationFrame(wxWindow* parent, wxWindowID id = wxID_ANY,
        const wxString& title = wxT("Documentation"),
        const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxSize(500, 400))
        : wxFrame(parent, id, title, pos, size) {

        wxHtmlWindow* htmlWindow = new wxHtmlWindow(this);
        htmlWindow->LoadPage("documentation.html");
    }
};
#endif