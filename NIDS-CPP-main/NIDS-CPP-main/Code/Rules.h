#ifndef RULES_H
#define RULES_H
#include "App.h"
#include <nlohmann/json.hpp> 
using json = nlohmann::json;

//Struct

template<typename T>
T tryGet(const json& jsonData, const std::string& key, const T& defaultValue) {
    try {
        return jsonData.at(key).get<T>();
    }
    catch (const json::exception&) {
        return defaultValue;
    }
}
//Struct to store rules from the JSON
struct RULE_Struct {
    std::array<uint8_t, 4> IPV4_Source;
    std::array<uint8_t, 4> IPV4_Destination;
    std::array<uint8_t, 16> IPV6_Source;
    std::array<uint8_t, 16> IPV6_Destination;
    std::array<uint8_t, 6> MAC_Source;
    std::array<uint8_t, 6> MAC_Destination;
    uint16_t port_Source;
    uint16_t port_Destination;
    uint16_t packetSize;
    uint32_t sequenceNumber;

    std::string alertType;

    uint32_t ruleNumber;

    // Constructor for convenience
    RULE_Struct(
        const std::array<uint8_t, 4>& ipv4Src = { 0, 0, 0, 0 },
        const std::array<uint8_t, 4>& ipv4Dest = { 0, 0, 0, 0 },
        const std::array<uint8_t, 16>& ipv6Src = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        const std::array<uint8_t, 16>& ipv6Dest = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        const std::array<uint8_t, 6>& macSrc = { 0, 0, 0, 0, 0, 0 },
        const std::array<uint8_t, 6>& macDest = { 0, 0, 0, 0, 0, 0 },
        const uint16_t portSrc = 0,
        const uint16_t portDest = 0,
        const uint16_t size = 0,
        const uint32_t seqNum = 0,
        const std::string alert = "None",
        const uint32_t rule = 0
    ) :
        IPV4_Source(ipv4Src),
        IPV4_Destination(ipv4Dest),
        IPV6_Source(ipv6Src),
        IPV6_Destination(ipv6Dest),
        MAC_Source(macSrc),
        MAC_Destination(macDest),
        port_Source(portSrc),
        port_Destination(portDest),
        packetSize(size),
        sequenceNumber(seqNum),
        alertType(alert),
        ruleNumber(rule) {}

    //Equality operator     ==
    bool operator==(const RULE_Struct& other) const {
        return IPV4_Source == other.IPV4_Source &&
            IPV4_Destination == other.IPV4_Destination &&
            IPV6_Source == other.IPV6_Source &&
            IPV6_Destination == other.IPV6_Destination &&
            port_Source == other.port_Source &&
            port_Destination == other.port_Destination &&
            packetSize == other.packetSize &&
            sequenceNumber == other.sequenceNumber &&
            alertType == other.alertType;
    }
};

//Declare RuleFrame Function
class RuleFrame : public wxDialog {
public:
    RuleFrame(wxWindow* parent, const wxString& title, const wxPoint& pos, const wxSize& size);
    
private:
    void OnStartCapture(wxCommandEvent& event);
    void OnLoadRules(wxCommandEvent& event);
    std::vector<RULE_Struct> RulesVector;

    wxButton* m_LoadRule;


    wxTextCtrl* m_ruleInput;
    wxTextCtrl* m_RuleOutput;
    //~RuleFrame();
    wxDECLARE_EVENT_TABLE();
};

//Some Shortcut
std::array<uint8_t, 4> IPV4_STR_BYTE(const std::string& ipString);
std::array<uint8_t, 16> IPV6_STR_BYTE(const std::string& ipString);
std::string IPV4_BYTE_STR(const std::array<uint8_t, 4>& byteArray);
std::string IPV6_BYTE_STR(const std::array<uint8_t, 16>& byteArray);
void CleanDuplicate_RuleStruct(std::vector<RULE_Struct>& myVector);

#endif