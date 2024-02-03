//Our Header File
#include "App.h"
#include "Rules.h"

//External Libs
#include <pcap.h>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>


#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif


//Rule Frame
wxBEGIN_EVENT_TABLE(RuleFrame, wxDialog)
EVT_BUTTON(1000, RuleFrame::OnLoadRules)
EVT_COMMAND(wxID_ANY, wxEVT_CUSTOM_TEXT_APPEND, NIDSFrame::OnTextAppend)
wxEND_EVENT_TABLE()

//Rule GUI
RuleFrame::RuleFrame(wxWindow* parent, const wxString& title, const wxPoint& pos, const wxSize& size) : wxDialog(parent, wxID_ANY, title, pos, size, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
{
    // Creez un objet wxFont pour personnaliser la police
    wxFont font(12, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    wxFont fontButton(9, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);

    // Creez un objet wxColour pour personnaliser les couleurs
    wxColour bg_color(245, 245, 245); // Un gris clair
    wxColour button_bg_color(70, 130, 180); // Bleu clair
    wxColour button_fg_color(*wxWHITE);
    wxColour text_ctrl_bg_color(*wxWHITE);
    wxColour text_ctrl_fg_color(0, 0, 0);
    wxColour gauge_color(50, 150, 250);

    // Appliquez les styles, polices et couleurs
    this->SetBackgroundColour(bg_color);

    // Initialize your controls in the new frame
    wxPanel* RuleSettingsPanel = new wxPanel(this);

    //Button
    m_LoadRule = new StyledButton(RuleSettingsPanel, 1000, "Charger les regles", wxPoint(10, 10), wxSize(130, 32), button_bg_color, button_fg_color, fontButton);

    //Text window
    m_ruleInput = new wxTextCtrl(RuleSettingsPanel, wxID_ANY, "Regle de detection...", wxPoint(10, 50), wxSize(200, 25));
    m_ruleInput->SetFont(font);

    m_RuleOutput = new wxTextCtrl(RuleSettingsPanel, wxID_ANY, "", wxPoint(10, 80), wxSize(400, 450), wxTE_MULTILINE | wxTE_READONLY);
    m_RuleOutput->SetFont(font);
}

//Butons action
//Load JSON FILE
void RuleFrame::OnLoadRules(wxCommandEvent& event) {
    wxFileDialog openFileDialog(this, "Open JSON File", wxEmptyString, wxEmptyString,
        "JSON files (*.json)|*.json", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    // Show the dialog and get the result
    if (openFileDialog.ShowModal() == wxID_OK) {
        wxString filePath = openFileDialog.GetPath();
        wxLogMessage("Selected JSON file: %s", filePath);

        std::ifstream file(filePath.ToStdString());
        if (!file.is_open()) {
            wxLogError("Failed to open JSON file.");
            return;
        }

        nlohmann::json jsonData;
        try {
            file >> jsonData;
        }
        catch (const std::exception& e) {
            wxLogError("Error parsing JSON: %s", e.what());
            return;
        }

        try {
            int counter = 0;
            for (int i = 0, counter = 0; i < jsonData.size(); i++, counter++) {
                std::string ruleIndex = "Rule_" + std::to_string(counter);
                if (jsonData.find(ruleIndex) != jsonData.end()) {
                    // Rule_x
                    RulesVector.push_back(
                        RULE_Struct(
                            IPV4_STR_BYTE(tryGet<std::string>(jsonData.at(ruleIndex).value("IPV4", json::object()), "Source", "0.0.0.0")),
                            IPV4_STR_BYTE(tryGet<std::string>(jsonData.at(ruleIndex).value("IPV4", json::object()), "Destination", "0.0.0.0")),
                            IPV6_STR_BYTE(tryGet<std::string>(jsonData.at(ruleIndex).value("IPV6", json::object()), "Source", "::")),
                            IPV6_STR_BYTE(tryGet<std::string>(jsonData.at(ruleIndex).value("IPV6", json::object()), "Destination", "::")),
                            {},
                            {},
                            tryGet<uint16_t>(jsonData.at(ruleIndex).value("Port", json::object()), "Source", 0),
                            tryGet<uint16_t>(jsonData.at(ruleIndex).value("Port", json::object()), "Destination", 0),
                            tryGet<uint16_t>(jsonData.at(ruleIndex), "PacketSize", 0),
                            tryGet<uint32_t>(jsonData.at(ruleIndex), "SequenceNumber", 0),
                            tryGet<std::string>(jsonData.at(ruleIndex), "AlertType", "None"),
                            static_cast<uint32_t>(counter)
                            /*
                            IPV4_STR_BYTE(jsonData.at(ruleIndex).at("IPV4").at("Source").get<std::string>()),
                            IPV4_STR_BYTE(jsonData.at(ruleIndex).at("IPV4").at("Destination").get<std::string>()),
                            IPV6_STR_BYTE(jsonData.at(ruleIndex).at("IPV6").at("Source").get<std::string>()),
                            IPV6_STR_BYTE(jsonData.at(ruleIndex).at("IPV6").at("Destination").get<std::string>()),
                            jsonData.at(ruleIndex).at("Port").at("Source").get<uint16_t>(),
                            jsonData.at(ruleIndex).at("Port").at("Destination").get<uint16_t>(),
                            jsonData.at(ruleIndex).at("PacketSize").get<uint16_t>(),
                            jsonData.at(ruleIndex).at("SequenceNumber").get<uint32_t>(),
                            static_cast<uint32_t>(i)*/
                        )
                    );
                }
                else {
                    i--;
                }
            }
        }
        catch (const std::exception& e)
        {
            wxLogError("Error accessing JSON values: %s", e.what());
        }
        CleanDuplicate_RuleStruct(RulesVector);
        // Print the values (for demonstration)
        for (size_t i = 0; i < RulesVector.size(); ++i)
        {
            m_RuleOutput->AppendText(wxString::Format("Rule: %d \n", RulesVector[i].ruleNumber));
            m_RuleOutput->AppendText(wxString::Format("  IPV4 Source: %s", IPV4_BYTE_STR(RulesVector[i].IPV4_Source)));
            m_RuleOutput->AppendText(wxString::Format("  IPV4 Destination: %s", IPV4_BYTE_STR(RulesVector[i].IPV4_Destination)));
            m_RuleOutput->AppendText(wxString::Format("  IPV6 Source: %s", IPV6_BYTE_STR(RulesVector[i].IPV6_Source)));
            m_RuleOutput->AppendText(wxString::Format("  IPV6 Destination: %s", IPV6_BYTE_STR(RulesVector[i].IPV6_Destination)));
            m_RuleOutput->AppendText(wxString::Format("  IPV4 Source: %s", IPV4_BYTE_STR(RulesVector[i].IPV4_Source)));
            m_RuleOutput->AppendText(wxString::Format("  Type: %s", RulesVector[i].alertType));
            
            /*
            wxLogMessage("Rule: %d", RulesVector[i].ruleNumber);
            wxLogMessage("  IPV4 Source: %s", IPV4_BYTE_STR(RulesVector[i].IPV4_Source));
            wxLogMessage("  IPV4 Destination: %s", IPV4_BYTE_STR(RulesVector[i].IPV4_Destination));
            wxLogMessage("  IPV6 Source: %s", IPV6_BYTE_STR(RulesVector[i].IPV6_Source));
            wxLogMessage("  IPV6 Destination: %s", IPV6_BYTE_STR(RulesVector[i].IPV6_Destination));
            wxLogMessage("  Type: %s", RulesVector[i].alertType);*/
            // Print more values as needed
        }

    }
}
//Do nothing
void RuleFrame::OnStartCapture(wxCommandEvent& event){}
//Do nothing
void NIDSFrame::processAlert(const wxString& alertMessage) {
    /*// Ajouter le message d'alerte à la liste des alertes stockées
    alertMessages.push_back(alertMessage);

    // Ajouter le message d'alerte à l'affichage de l'interface utilisateur
    if (m_alertDisplay != nullptr) {
        m_alertDisplay->AppendText(alertMessage + wxT("\n"));
    }*/
}
//Do nothing
void NIDSFrame::OnAddDetectionRule(wxCommandEvent& event) {/*
    wxString rule = m_ruleInput->GetValue();
    unsigned int packetSize = std::stoi(std::string(rule.mb_str())); // Convertit la règle en entier
    packetSizeRules.push_back(packetSize);
    m_ruleInput->Clear();
    m_alertDisplay->AppendText("Règle de taille de paquet ajoutée : " + rule + "\n");*/
}
//Do nothing
void NIDSFrame::OnShowAlerts(wxCommandEvent& event) {/*
    wxString allAlerts;
    for (const auto& alert : alertMessages) {
        allAlerts += alert; // Ajouter chaque alerte à la chaîne
    }

    // Affiche toutes les alertes dans m_alertDisplay
    m_alertDisplay->SetValue(allAlerts); */
}


//Convertion: IP->Byte ; Byte->IP
std::array<uint8_t, 4> IPV4_STR_BYTE(const std::string& ipString) {
    std::array<uint8_t, 4> byteArray;

#ifdef _WIN32
    if (inet_pton(AF_INET, ipString.c_str(), byteArray.data()) == 1) {
        return byteArray;
    }
#else
    if (inet_pton(AF_INET, ipString.c_str(), byteArray.data()) == 1) {
        return byteArray;
    }
#endif

    // If conversion fails, set the array to a default value or handle the error as needed.
    byteArray.fill(0);
    return byteArray;
}
std::array<uint8_t, 16> IPV6_STR_BYTE(const std::string& ipString) {
    std::array<uint8_t, 16> byteArray;

#ifdef _WIN32
    std::wstring ipv6WideString(ipString.begin(), ipString.end());
    sockaddr_in6 sa;
    int result = InetPton(AF_INET6, ipv6WideString.c_str(), &sa.sin6_addr);
    if (result == 1) {
        memcpy(byteArray.data(), &sa.sin6_addr, 16);
        return byteArray;
    }
#else
    addrinfo hints, * res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;

    int result = getaddrinfo(ipString.c_str(), NULL, &hints, &res);
    if (result == 0) {
        memcpy(byteArray.data(), &((sockaddr_in6*)res->ai_addr)->sin6_addr, 16);
        freeaddrinfo(res);
        return byteArray;
    }
#endif

    // If conversion fails, set the array to a default value or handle the error as needed.
    byteArray.fill(0);
    return byteArray;
}
std::string IPV4_BYTE_STR(const std::array<uint8_t, 4>& byteArray) {
    std::ostringstream oss;
    oss << static_cast<int>(byteArray[0]) << "."
        << static_cast<int>(byteArray[1]) << "."
        << static_cast<int>(byteArray[2]) << "."
        << static_cast<int>(byteArray[3]);
    return oss.str();
}
std::string IPV6_BYTE_STR(const std::array<uint8_t, 16>& byteArray) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    bool leadingZeros = false;

    for (int i = 0; i < 16; i += 2) {
        int value = (byteArray[i] << 8) + byteArray[i + 1];
        if (value == 0 && !leadingZeros) {
            leadingZeros = true;
            oss << "::";
        }
        else if (i > 0 && value == 0 && leadingZeros) {
            // Skip consecutive zeros
        }
        else {
            if (i > 0) oss << ":";
            oss << std::setw(4) << value;
        }
    }

    return oss.str();
}
void CleanDuplicate_RuleStruct(std::vector<RULE_Struct>& myVector) {
    std::sort(myVector.begin(), myVector.end(), [](const RULE_Struct& a, const RULE_Struct& b) {
        return std::tie(
            a.ruleNumber
        ) < std::tie(
            b.ruleNumber
        );
        });

    // Use std::unique with a custom comparison function
    auto last = std::unique(myVector.begin(), myVector.end(), [](const RULE_Struct& a, const RULE_Struct& b) {
        return a == b;
        });

    // Erase the duplicates
    myVector.erase(last, myVector.end());
}
