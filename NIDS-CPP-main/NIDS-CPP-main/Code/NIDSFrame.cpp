#pragma comment(lib, "Ws2_32.lib")
//Our Header File
#include "App.h"
#include "Rules.h"
#include "PacketHandler.h"
#include "NetworkStructures.h"
#include "DDoSDetector.h"

//External Libs
#include <pcap.h>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <array>
#include <iostream>
#include <fstream>
#include <filesystem>


#define ID_HELP_DOCUMENTATION 1009
DDoSDetector ddosDetector;
namespace fs = std::filesystem;

//VAR
bool intrusionDetected = false;
wxString someInfo = "Aucune information d'intrusion d�tect�e";

std::vector<unsigned int> packetSizeRules;

// Define the custom event type using the wxDEFINE_EVENT macro.


//Other Define
wxString ByteArrayTo_wxStringHex(const std::vector<uint8_t>& byteArray);
template <size_t N> wxString ByteArrayTo_wxString(const std::array<uint8_t, N>& byteArray);
wxString IPv4ArrayToDecimalString(const std::array<uint8_t, 4>& ipv4Array);
wxString IPv6ArrayToHexString(const std::array<uint8_t, 16>& ipv6Array);
void SavePacket(const std::string& filename, const u_char* packet, uint32_t size);
wxDEFINE_EVENT(wxEVT_CUSTOM_TEXT_APPEND, wxCommandEvent);

//Thread
NIDSFrame::~NIDSFrame() {
    if (captureThread.joinable()) {
        pcap_breakloop(handle);
        captureThread.join();
        pcap_close(handle);
    }
}

//Button Declare ?
wxBEGIN_EVENT_TABLE(NIDSFrame, wxFrame)
EVT_BUTTON(1001, NIDSFrame::OnStartCapture)
EVT_BUTTON(1002, NIDSFrame::OnStopCapture)
EVT_BUTTON(1003, NIDSFrame::OnAddDetectionRule)
EVT_BUTTON(1005, NIDSFrame::OnClearDisplay)
EVT_BUTTON(1006, NIDSFrame::OnSaveLogs)
EVT_BUTTON(1008, NIDSFrame::OnSaveAlerts)
EVT_BUTTON(1009, NIDSFrame::RuleFrameLoader)
EVT_BUTTON(1010, NIDSFrame::alertTester)

EVT_COMMAND(wxID_ANY, wxEVT_CUSTOM_TEXT_APPEND, NIDSFrame::OnTextAppend)
EVT_MENU(ID_HELP_DOCUMENTATION, NIDSFrame::OnOpenDocumentation)
wxEND_EVENT_TABLE()

//GUI
NIDSFrame::NIDSFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
    : wxFrame(NULL, wxID_ANY, title, pos, size) {
    SetDoubleBuffered(true);
    // Cr�ez un objet wxFont pour personnaliser la police
    wxFont font(12, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    wxFont fontButton(9, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);

    // Cr�ez un objet wxColour pour personnaliser les couleurs
    wxColour bg_color(245, 245, 245); // Un gris clair
    wxColour button_bg_color(70, 130, 180); // Bleu clair
    wxColour button_fg_color(*wxWHITE);
    wxColour text_ctrl_bg_color(*wxWHITE);
    wxColour text_ctrl_fg_color(0, 0, 0);
    wxColour gauge_color(50, 150, 250);

    // Appliquez les styles, polices et couleurs
    this->SetBackgroundColour(bg_color);

    //==================================================== ManuBar =================================================
    //logo header
    wxImage::AddHandler(new wxPNGHandler());
    wxToolBar* toolbar = CreateToolBar();

    // Créez le bitmap pour l'icône
    wxBitmap toolBarBitmap(wxT("logo.png"), wxBITMAP_TYPE_ANY);

    // Ajoutez l'icône à la barre d'outils
    int toolId = toolbar->AddTool(wxID_ANY, wxEmptyString, toolBarBitmap)->GetId();

    wxFont toolBarFont(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Lato"));
    wxStaticText* toolbarText = new wxStaticText(toolbar, wxID_ANY, wxT("Brain's dead weight"));
    toolbarText->SetFont(toolBarFont);
    toolbar->AddControl(toolbarText);

    // Finalisez la barre d'outils
    toolbar->Realize();

    //=================MENU=====================//

    wxMenuBar* menuBar = new wxMenuBar();

    wxMenu* fileMenu = new wxMenu();
    wxMenu* exportSubMenu = new wxMenu();
    wxMenu* toolsMenu = new wxMenu();
    wxMenu* viewMenu = new wxMenu();
    wxMenu* settingsMenu = new wxMenu();
    wxMenu* helpMenu = new wxMenu();

    menuBar->Append(fileMenu, wxT("&Fichier"));
    menuBar->Append(toolsMenu, wxT("&Outils"));
    menuBar->Insert(2, viewMenu, wxT("&Vue"));
    menuBar->Append(settingsMenu, wxT("&Réglages"));
    menuBar->Append(helpMenu, wxT("&Aide"));

    // file menu
    fileMenu->Append(wxID_ANY, wxT("Nouvelle Capture\tCtrl-N"), wxT("Commencer une nouvelle capture"));
    fileMenu->Append(wxID_ANY, wxT("Enregistrer Log\tCtrl-S"), wxT("Enregistrer le log des captures"));

    exportSubMenu->Append(wxID_ANY, wxT("Exporter les Logs"), wxT("Exporter les logs en format CSV"));
    exportSubMenu->Append(wxID_ANY, wxT("Exporter les Alertes"), wxT("Exporter les alertes en format JSON"));

    fileMenu->AppendSubMenu(exportSubMenu, wxT("Exporter"));
    fileMenu->Append(wxID_ANY, wxT("Importer les règles"), wxT("Importer des règles depuis un fichier"));
    fileMenu->AppendSeparator();
    fileMenu->Append(wxID_EXIT, wxT("Quitter\tCtrl-Q"), wxT("Quitter l'application"));

    //tool menu
    toolsMenu->Append(wxID_ANY, wxT("Paramètres"), wxT("Configurer les paramètres du NIDS"));
    toolsMenu->Append(wxID_ANY, wxT("Mettre à jour les signatures"), wxT("Mettre à jour la base de données des signatures"));

    //view menu
    viewMenu->AppendCheckItem(wxID_ANY, wxT("Afficher les détails des paquets"), wxT("Basculer l'affichage des détails des paquets"));
    viewMenu->AppendCheckItem(wxID_ANY, wxT("Afficher les statistiques de trafic"), wxT("Basculer l'affichage des statistiques de trafic"));

    //reglage menu 
    settingsMenu->Append(wxID_ANY, wxT("Préférences"), wxT("Modifier les préférences du système"));
    settingsMenu->Append(wxID_ANY, wxT("Gestion des utilisateurs"), wxT("Gérer les comptes utilisateurs"));

    //Help Menu
    helpMenu->Append(wxID_ABOUT, wxT("À propos"), wxT("Informations sur l'application"));
    helpMenu->Append(ID_HELP_DOCUMENTATION, wxT("Documentation"), wxT("Consulter la documentation de l'application"));
    helpMenu->Append(wxID_ANY, wxT("Support technique"), wxT("Contacter le support technique"));

    //Gestion évenements
    Bind(wxEVT_MENU, &NIDSFrame::OnExit, this, wxID_EXIT);
    Bind(wxEVT_MENU, &NIDSFrame::OnAbout, this, wxID_ABOUT);

    //set menu bar
    SetMenuBar(menuBar);


    //=================BUTTON=================//
    m_startButton =         new StyledButton(toolbar, 1001, "Demarrer la capture", wxPoint(250, 0), wxSize(140, 32), button_bg_color, button_fg_color, fontButton);
    m_stopButton =          new StyledButton(toolbar, 1002, "Arreter la capture", wxPoint(390, 0), wxSize(130, 32), button_bg_color, button_fg_color, fontButton);
    m_clearDisplayButton =  new StyledButton(toolbar, 1005, "Effacer l'affichage", wxPoint(520, 0), wxSize(130, 32), button_bg_color, button_fg_color, fontButton);
    m_ruleFrameLoader =     new StyledButton(toolbar, 1009, "Rules Settings", wxPoint(1010, 0), wxSize(130, 32), button_bg_color, button_fg_color, fontButton);
    m_testAlert =           new StyledButton(toolbar, 1010, "Test Alert", wxPoint(830, 0), wxSize(180, 40), button_bg_color, button_fg_color, font);
    m_saveLogsButton =      new StyledButton(this, 1006, "Enregistrer les journaux", wxPoint(10, 650), wxSize(180, 40), button_bg_color, button_fg_color, font);
    m_saveAlertsButton =    new StyledButton(this, 1008, "Enregistrer les Alertes", wxPoint(190, 650), wxSize(180, 40), button_bg_color, button_fg_color, font);
    

    wxStaticText* label = new wxStaticText(this, wxID_ANY, "Choisir une interface:", wxPoint(10, 70));
    label->SetFont(font);

    m_interfaceChoice = new wxChoice(this, wxID_ANY, wxPoint(10, 90), wxSize(650, 25));
    m_interfaceChoice->SetFont(font);

    

    // Recuperer la liste des interfaces disponibles
    pcap_if_t* allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        // Gestion de l'erreur, par exemple, afficher un message d'erreur
    }
    else {
        // Parcourir la liste des interfaces et les ajouter au choix
        for (pcap_if_t* dev = allDevs; dev; dev = dev->next) {
            std::string InterfaceName = dev->description;
            do {
                InterfaceName += "_-";
            } while (std::string(InterfaceName).size() < 50);
            m_interfaceChoice->Append((std::string(InterfaceName) + std::string(dev->name)).c_str());
        }
        // Lib�rer la m�moire utilis�e pour la liste
        pcap_freealldevs(allDevs);
    }

    // Initialize the List Control
    m_packetListCtrl = new wxListCtrl(this, wxID_ANY, wxPoint(0, 150), wxSize(880, 400), wxLC_REPORT);
    m_packetListCtrl->InsertColumn(0, wxT("Number"), wxLIST_FORMAT_LEFT, 60);
    m_packetListCtrl->InsertColumn(1, wxT("Timestamp"), wxLIST_FORMAT_LEFT, 120);
    m_packetListCtrl->InsertColumn(2, wxT("Source IP"), wxLIST_FORMAT_LEFT, 85);
    m_packetListCtrl->InsertColumn(3, wxT("Destination IP"), wxLIST_FORMAT_LEFT, 85);
    m_packetListCtrl->InsertColumn(4, wxT("Length"), wxLIST_FORMAT_LEFT, 70);
    m_packetListCtrl->InsertColumn(5, wxT("Protocol"), wxLIST_FORMAT_LEFT, 60);
    m_packetListCtrl->InsertColumn(6, wxT("Data"), wxLIST_FORMAT_LEFT, 400);

    m_alertListControl = new wxListCtrl(this, wxID_ANY, wxPoint(900, 150), wxSize(400, 400), wxLC_REPORT);
    m_alertListControl->InsertColumn(0, wxT("Alert"), wxLIST_FORMAT_LEFT, 400);


    m_statusLabel = new wxStaticText(this, wxID_ANY, "Statut : En attente", wxPoint(10, 600));
    m_statusLabel->SetFont(font);

   
}

//Button
//Start capture
void NIDSFrame::OnStartCapture(wxCommandEvent& event) {
    // Implémenter la fonction de capture de paquets
    const wxString selectedInterface = m_interfaceChoice->GetStringSelection();
    char errbuf[PCAP_ERRBUF_SIZE];

    size_t lastDelimiterPos = selectedInterface.find("_-\\");
    std::string devicePath = (lastDelimiterPos != wxString::npos) ? selectedInterface.substr(lastDelimiterPos + 2).ToStdString() : selectedInterface.ToStdString();

    handle = pcap_open(devicePath.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);

    if (handle) {
        // Mettez à jour le statut en "Capture en cours"
        stopCaptureFlag = false;
        m_statusLabel->SetLabel("Statut : Capture en cours");
        captureThread = std::thread([this]() {
            pcap_loop(handle, 0, packetHandlerWrapper, reinterpret_cast<u_char*>(this));
            });
        chartDrawerThread = std::thread([this]() {
            wxWidgetChartDrawer();
            });
        packetScannerThread_NMAP = std::thread([this]() {
            packetScanner_NMAP();
            });
    }
    else {
        wxMessageBox(wxString("Erreur lors de l'ouverture de l'adaptateur : ") + wxString(errbuf), "Erreur", wxICON_ERROR);
    }
}
//Stop catpure
void NIDSFrame::OnStopCapture(wxCommandEvent& event) {
    // Impl�menter la fonction pour arr�ter la capture de paquets
    if (handle) {
        pcap_breakloop(handle);
        stopCaptureFlag = true;
        if (captureThread.joinable()) {
            captureThread.join();
        }
        if (chartDrawerThread.joinable()) {
            chartDrawerThread.join();
        }
        if (packetScannerThread_NMAP.joinable()) {
            packetScannerThread_NMAP.join();
        }

        pcap_close(handle);
        handle = nullptr;
        // Réinitialiser le texte du statut en "En attente"
        m_statusLabel->SetLabel("Statut : En attente");
    }
}
//Save whatever's in the packet display
void NIDSFrame::OnSaveLogs(wxCommandEvent& event) {
    // Ouvrir une boîte de dialogue pour sauvegarder le fichier
    wxFileDialog saveFileDialog(this, _("Enregistrer les journaux"), "", "",
        "Text files (*.txt)|*.txt", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (saveFileDialog.ShowModal() == wxID_CANCEL)
        return;     // l'utilisateur a changé d'avis

    // Créer et ouvrir un fichier de sortie
    std::ofstream outFile(saveFileDialog.GetPath().ToStdString(), std::ios::out);
    if (!outFile.is_open()) {
        wxMessageBox("Impossible d'ouvrir le fichier pour l'écriture.", "Erreur", wxICON_ERROR);
        return;
    }

    // Écrire les informations de capture de paquet dans le fichier
    for (long i = 0; i < m_packetListCtrl->GetItemCount(); ++i) {
        wxString timestamp = m_packetListCtrl->GetItemText(i, 0);
        wxString length = m_packetListCtrl->GetItemText(i, 1);
        wxString srcIP = m_packetListCtrl->GetItemText(i, 2);
        wxString destIP = m_packetListCtrl->GetItemText(i, 3);
        wxString data = m_packetListCtrl->GetItemText(i, 4);

        outFile << timestamp.ToStdString() << ", "
            << length.ToStdString() << ", "
            << srcIP.ToStdString() << ", "
            << destIP.ToStdString() << ", "
            << data.ToStdString() << "\n";
    }

    // Écrire les alertes dans le fichier
    outFile << "\nAlertes:\n";
    for (const auto& alert : alertMessages) {
        outFile << alert.ToStdString() << "\n";
    }

    outFile.close();
    wxMessageBox("Les journaux ont été sauvegardés avec succès.", "Succès", wxICON_INFORMATION);
}
//Save whatever's in the alert display
void NIDSFrame::OnSaveAlerts(wxCommandEvent& event) {
    // Ouvrir une boîte de dialogue pour sauvegarder le fichier
    wxFileDialog saveFileDialog(this, _("Save Alerts"), "", "",
        "Text files (*.txt)|*.txt", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (saveFileDialog.ShowModal() == wxID_CANCEL)
        return;     // l'utilisateur a changé d'avis

    // Créer et ouvrir un fichier de sortie
    std::ofstream outFile(saveFileDialog.GetPath().ToStdString(), std::ios::out);
    if (!outFile.is_open()) {
        wxMessageBox("Impossible d'ouvrir le fichier pour l'écriture.", "Erreur", wxICON_ERROR);
        return;
    }

    for (long i = 0; i < m_alertListControl->GetItemCount(); ++i) {
        wxString AlertString = m_alertListControl->GetItemText(i, 0);

        outFile << AlertString.ToStdString() << "\n";
    }

    // Écrire les alertes dans le fichier
    for (const auto& alert : alertMessages) {
        outFile << alert.ToStdString() << "\n";
    }

    outFile.close();

}
//Triger the opening of the frame RuleLoader
void NIDSFrame::RuleFrameLoader(wxCommandEvent& event)
{
    RuleFrame ruleFrame(this, "Rules settings", wxDefaultPosition, wxSize(800, 600));

    // Show the dialog modally
    if (ruleFrame.ShowModal() == wxID_OK) {
        // Handle the result if needed
    }
}
//Triger the opening of documentation Frame
void NIDSFrame::OnOpenDocumentation(wxCommandEvent& event) {
    DocumentationFrame* docFrame = new DocumentationFrame(this);
    docFrame->Show(true);
}
//Used by a thread to print the packet captured on screen
void NIDSFrame::wxWidgetChartDrawer() {
    int Location = 0;
    wxString srcIP;
    wxString destIP;
    wxString packetData;
    wxString packetLenght;
    wxString Protocolss;

    while (!stopCaptureFlag) {
        int VectorSize = PacketStructVector.size();
        for (Location; Location < VectorSize; Location++) {
            long itemIndex = m_packetListCtrl->InsertItem(m_packetListCtrl->GetItemCount(), wxString::Format("%d", m_packetListCtrl->GetItemCount()));

            if (PacketStructVector[Location].IP_Type == 0x0008) {
                //IPV4 Print
                
                switch (PacketStructVector[Location].Protocol) {
                case 6:
                    Protocolss = "TCP";
                    break;
                case 17:
                    Protocolss = "UDP";
                    break;
                default:
                    Protocolss = wxString::Format("%d", PacketStructVector[Location].Protocol);
                    break;
                }

                srcIP = IPv4ArrayToDecimalString(PacketStructVector[Location].IPV4_Source);
                destIP = IPv4ArrayToDecimalString(PacketStructVector[Location].IPV4_Destination);
                packetData = ByteArrayTo_wxStringHex(PacketStructVector[Location].Payload);
                packetLenght = wxString::Format(wxT("%d"), PacketStructVector[Location].packetSize);

            }
            else if (PacketStructVector[Location].IP_Type == 0xDD86) {
                srcIP = IPv6ArrayToHexString(PacketStructVector[Location].IPV6_Source);
                destIP = IPv6ArrayToHexString(PacketStructVector[Location].IPV6_Destination);
                packetData = "Unknown";
                packetLenght = "Unknown";
                Protocolss = "Unknown";

            }

            m_packetListCtrl->SetItem(itemIndex, 1, wxString::Format("%ld.%06ld", long(PacketStructVector[Location].tv_sec), long(PacketStructVector[Location].tv_usec)));
            m_packetListCtrl->SetItem(itemIndex, 2, srcIP);
            m_packetListCtrl->SetItem(itemIndex, 3, destIP);
            m_packetListCtrl->SetItem(itemIndex, 4, packetLenght);
            m_packetListCtrl->SetItem(itemIndex, 5, Protocolss);
            m_packetListCtrl->SetItem(itemIndex, 6, packetData);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}
//Look for SYN in a TCP packet and warn
void NIDSFrame::packetScanner_NMAP() {
    int Location = 0;
    wxString alertInfo = "No";

    while (!stopCaptureFlag) {
        int VectorSize = PacketStructVector.size();
        uint8_t Flags;
        std::vector<NmapBuffer> NmapBufferVector;

        /*
        int RuleListSize = RulesVector.size();
        if (RuleListSize > 2) {
            //Limit size for speed, i don't have the time for efficient algorithm rn
            RuleListSize = 2;
        }*/

        for (Location; Location < VectorSize; Location++) {
            PacketStructVector[Location].IPV4_Source;

            /*for (int i = 0; i < RuleListSize; i++) {
                if (std::memcmp(PacketStructVector[Location].IPV4_Source.data(), RulesVector[i].IPV4_Source.data(), 4) == 0||
                    std::memcmp(PacketStructVector[Location].IPV4_Destination.data(), RulesVector[i].IPV4_Destination.data(), 4) == 0 ||
                    std::memcmp(PacketStructVector[Location].MAC_Source.data(), RulesVector[i].MAC_Source.data(), 6) == 0 ||
                    std::memcmp(PacketStructVector[Location].MAC_Destination.data(), RulesVector[i].MAC_Destination.data(), 6) == 0
                    ) {
                    // Print that the packet is from a dangerous source base on the rules
                }
            }*/

            if (PacketStructVector[Location].Protocol == 6) {
                //TCP so check for nmap
                Flags = PacketStructVector[Location].Flags;
                Flags &= 0x01000000; // Isolate SYN Flags from other flags
                if (Flags == 0x01000000) {
                    // Check if the IP is already in NmapBufferVector
                    auto it = std::find_if(NmapBufferVector.begin(), NmapBufferVector.end(), [&](const NmapBuffer& buffer) {
                        return std::memcmp(PacketStructVector[Location].IPV4_Source.data(), buffer.IPV4.data(), 4) == 0;
                        });

                    if (it != NmapBufferVector.end()) {
                        // IP found in NmapBufferVector, update the information
                        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - it->Delay).count() > 60) {
                            it->OpeningRequest = 0;
                        }
                        it->OpeningRequest += 1;
                        it->Delay = std::chrono::system_clock::now();
                        // Check if more than 60 seconds have passed, reset OpeningRequest
                        if (it->OpeningRequest > 5) {
                            //NMAP Detected
                            std::time_t time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                            std::tm* timeinfo = std::localtime(&time);
                            alertInfo = wxString::Format("NMAP SCAN Suspected.  %d.%d.%d.%d is having a supicious behavior. Last Activity: %02d-%02d %02d:%02d:%02d",
                                PacketStructVector[Location].IPV4_Source[0],
                                PacketStructVector[Location].IPV4_Source[1],
                                PacketStructVector[Location].IPV4_Source[2],
                                PacketStructVector[Location].IPV4_Source[3],
                                timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                            m_alertListControl->InsertItem(m_packetListCtrl->GetItemCount(), alertInfo);
                        }
                    }
                    else {
                        // IP not found, add a new entry to NmapBufferVector
                        NmapBuffer newBuffer;
                        newBuffer.IPV4 = PacketStructVector[Location].IPV4_Source;
                        newBuffer.OpeningRequest = 1;
                        newBuffer.Delay = std::chrono::system_clock::now();
                        NmapBufferVector.push_back(newBuffer);
                    }
                }
            }
                
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}
//Pickc the first TCP IPV4 packet and show the sasme message show when a nmap is detected
void NIDSFrame::alertTester(wxCommandEvent& event) {
    wxString alertInfo = "No";

    while (!stopCaptureFlag) {
        int VectorSize = PacketStructVector.size();

        for (LocationAlertTest; LocationAlertTest < VectorSize; LocationAlertTest++) {
            PacketStructVector[LocationAlertTest].IPV4_Source;
            if (PacketStructVector[LocationAlertTest].Protocol == 6) {
                //NMAP Detected
                std::time_t time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                std::tm* timeinfo = std::localtime(&time);
                alertInfo = wxString::Format("NMAP SCAN Suspected.  %d.%d.%d.%d is having a supicious behavior. Last Activity: %02d-%02d %02d:%02d:%02d",
                    PacketStructVector[LocationAlertTest].IPV4_Source[0],
                    PacketStructVector[LocationAlertTest].IPV4_Source[1],
                    PacketStructVector[LocationAlertTest].IPV4_Source[2],
                    PacketStructVector[LocationAlertTest].IPV4_Source[3],
                    timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                m_alertListControl->InsertItem(m_packetListCtrl->GetItemCount(), alertInfo);
                break;
            }
        }
        break;
    }
}

//Worker
void NIDSFrame::packetHandlerWrapper(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    NIDSFrame* frame = reinterpret_cast<NIDSFrame*>(user);
    frame->packetHandler(pkthdr, packet);
}
//Extract information from captured packet
void NIDSFrame::packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    SavePacket("filename.bin", packet, pkthdr->len);
    
    PacketStruct packetStruct;
    bool intrusionDetected = false;

    packetStruct.IP_Type = 0;
    packetCounter++;

    packetStruct.port_Source = 0;
    packetStruct.packetSize = 0;

    
    packetStruct.tv_sec = pkthdr->ts.tv_sec;
    packetStruct.tv_usec = pkthdr->ts.tv_usec;
 
    std::memcpy(&packetStruct.IP_Type, packet + 12, 2);


    std::memcpy(packetStruct.MAC_Destination.data(), packet, 6);
    std::memcpy(packetStruct.MAC_Source.data(), packet + 6, 6);

    if (packetStruct.IP_Type == 0x0008)  {
        //IPV4 Header
        std::memcpy(&packetStruct.packetSize, packet + 16, 2);
        packetStruct.packetSize -= 14; //Minus Internet Header

        std::memcpy(&packetStruct.IHL, packet + 14, 1);
        packetStruct.IHL &= 0x0f; //Remove the Version and keep just ihl
        
        std::memcpy(&packetStruct.Protocol, packet + 23, 1);
        std::memcpy(packetStruct.IPV4_Source.data(), packet + 26, 4);
        std::memcpy(packetStruct.IPV4_Destination.data(), packet + 30, 4);
        
        
        if (packetStruct.IHL < 5) {
            //must somehow stop the process for this packet
            wxLogMessage("Error Capturing packet: IPV4 Header Corruption");
        }

        int IHL_Offset = (packetStruct.IHL * 4) + 14;
        
        //Protocol Header
        // Read: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        if (packetStruct.Protocol == 6) {
            //TCP Protocol number
            //Create a TCP function and pass all args as pointer but i'm lazy right now
            std::memcpy(&packetStruct.port_Source, packet + IHL_Offset, 2);
            std::memcpy(&packetStruct.port_Destination, packet + IHL_Offset + 2, 2);
            std::memcpy(&packetStruct.sequenceNumber, packet + IHL_Offset + 4, 4);
            std::memcpy(&packetStruct.ACK, packet + IHL_Offset + 8, 4);

            std::memcpy(&packetStruct.Data_Offset, packet + IHL_Offset + 12, 1);
            packetStruct.Data_Offset &= 0xf0; //Remove the "Reserved" filed in the TCP header
            packetStruct.Data_Offset >>= 4;
            if (packetStruct.Data_Offset < 5) {
                //must somehow stop the process for this packet
                wxLogMessage("Error Capturing packet: TCP Header Corruption");
            }
            if (packetStruct.Data_Offset > 5) {
                //If options exist: retrieve them
                int temp_size = (packetStruct.Data_Offset - 4) * 4;
                packetStruct.Protocol_Option.reserve(temp_size);
                std::memcpy(packetStruct.Protocol_Option.data(), packet + IHL_Offset + 20, temp_size);
            }
            int Dt_offset = (packetStruct.Data_Offset * 4) + IHL_Offset;

            std::memcpy(&packetStruct.Flags, packet + IHL_Offset + 13, 1);
            std::memcpy(&packetStruct.Window_Size, packet + IHL_Offset + 14, 2);
            std::memcpy(&packetStruct.Checksum, packet + IHL_Offset + 16, 2);

            //Payload
            packetStruct.dataSize = packetStruct.packetSize - (packetStruct.IHL * 4) - (packetStruct.Data_Offset * 4); //Minus IPV4 Header Minus TCP Header
            packetStruct.Payload.resize(packetStruct.dataSize);
            std::memcpy(packetStruct.Payload.data(), packet + Dt_offset, packetStruct.dataSize);
        }
        if (packetStruct.Protocol == 17) {
            //UDP Protocol number
            //Create a UDP function and pass all args as pointer but i'm lazy right now
            std::memcpy(&packetStruct.port_Source, packet + IHL_Offset, 2);
            std::memcpy(&packetStruct.port_Destination, packet + IHL_Offset + 2, 2);
            std::memcpy(&packetStruct.Window_Size, packet + IHL_Offset + 4, 2);
            std::memcpy(&packetStruct.Checksum, packet + IHL_Offset + 6, 2);

            //Payload
            packetStruct.dataSize = packetStruct.Window_Size - 8; //Minus IPV4 Header Minus TCP Header
            packetStruct.Payload.reserve(packetStruct.dataSize);
            std::memcpy(packetStruct.Payload.data(), packet + IHL_Offset + 8, packetStruct.dataSize);
        }
        if (!(packetStruct.Protocol == 6 || packetStruct.Protocol == 17)) {
            //Gotta copy everything from then end of the IPV4 Header till the end of the packet but i'm lazy rn
        }
    }
    else if (packetStruct.IP_Type == 0xDD86) {
        //IPV6
        std::memcpy(packetStruct.IPV6_Source.data(), packet + 22, 16);
        std::memcpy(packetStruct.IPV6_Destination.data(), packet + 38, 16);
    }
    PacketStructVector.push_back(packetStruct);
}
//Doesn't work
bool NIDSFrame::checkForNmapScan(const u_char* packet, unsigned int length) {
    // Assurez-vous que la longueur est suffisante pour un en-tête IP et TCP
    if (length < sizeof(IPHDR) + sizeof(TCPHDR)) return false;

    const IPHDR* ipHeader = reinterpret_cast<const IPHDR*>(packet);
    unsigned int ipHeaderLength = ipHeader->ihl * 4;

    // Vérifiez si la longueur totale est suffisante pour inclure les en-têtes IP et TCP
    if (length < ipHeaderLength + sizeof(TCPHDR)) return false;

    // Pointez vers l'en-tête TCP qui suit immédiatement l'en-tête IP
    const TCPHDR* tcpHeader = reinterpret_cast<const TCPHDR*>(packet + ipHeaderLength);

    // Vérifiez pour un scan SYN typique Nmap (seul le drapeau SYN est défini)
    if ((tcpHeader->syn == 1) && (tcpHeader->ack == 0) && (tcpHeader->rst == 0) && (tcpHeader->fin == 0) && (tcpHeader->psh == 0) && (tcpHeader->urg == 0)) {
        // Un paquet avec seulement le drapeau SYN pourrait être une tentative de scan de ports
        return true;
    }

    // Ajouter ici d'autres logiques pour détecter d'autres types de scans Nmap

    return false;
}
//Doesn't work
bool NIDSFrame::checkForDDoS(const wxString& srcIP) {
    // Convertit srcIP de wxString à std::string
    std::string srcIpStd = srcIP.ToStdString();
    return ddosDetector.detectDDoS(srcIpStd);
}
//Add a line of text to m_packetDisplay
void NIDSFrame::OnTextAppend(wxCommandEvent& event) {
    m_packetDisplay->AppendText(event.GetString() + wxT("\n"));
}
//Close the NidsFrame
void NIDSFrame::OnExit(wxCommandEvent& event) {
    Close(true);
}
//Open the About Frame
void NIDSFrame::OnAbout(wxCommandEvent& event) {
    wxMessageBox(wxT("NIDS - Système de Détection d'Intrusion Réseau\n© 2023 PROJET C++"), wxT("À propos de NIDS"), wxOK | wxICON_INFORMATION);
}
//Clear both packet and alert display
void NIDSFrame::OnClearDisplay(wxCommandEvent& event) {
    m_packetListCtrl->DeleteAllItems();
    m_alertListControl->DeleteAllItems();
}

//Some convertion for convinence
wxString IPv4ArrayToDecimalString(const std::array<uint8_t, 4>& ipv4Array) {
    return wxString::Format(wxT("%u.%u.%u.%u"), ipv4Array[0], ipv4Array[1], ipv4Array[2], ipv4Array[3]);
}
wxString IPv6ArrayToHexString(const std::array<uint8_t, 16>& ipv6Array) {
    wxString hexString;

    bool leadingZero = false;  // Flag to track leading zeros in compressed form
    size_t consecutiveZeros = 0; // Count consecutive zero bytes

    for (size_t i = 0; i < ipv6Array.size(); ++i) {
        if (ipv6Array[i] != 0 || leadingZero) {
            // Add a colon if not the first byte and not in the middle of a run of leading zeros
            if (i != 0 && !leadingZero) {
                hexString << wxT(":");
            }

            // Append the two-digit hexadecimal representation
            hexString << wxString::Format(wxT("%02X"), ipv6Array[i]);

            // Reset the leadingZero flag and consecutiveZeros count
            leadingZero = false;
            consecutiveZeros = 0;
        }
        else {
            // If the byte is 0 and not the first byte, set the leadingZero flag
            if (i != 0) {
                leadingZero = true;
                // Increment consecutiveZeros count
                consecutiveZeros++;
            }
        }

        // If there are more than one consecutive zero bytes, replace them with double colon (::)
        if (consecutiveZeros > 1 && i + 1 < ipv6Array.size() && ipv6Array[i + 1] != 0) {
            hexString << wxT("::");
            leadingZero = false; // Reset the leadingZero flag
        }
    }

    return hexString;
}
template <size_t N>
wxString ByteArrayTo_wxString(const std::array<uint8_t, N>&byteArray) {
    wxString result;

    for (const auto& byte : byteArray) {
        // Convert each byte to its character representation and append to wxString
        result.append(wxString::Format(wxT("%c"), byte));
    }

    return result;
}
wxString ByteArrayTo_wxStringHex(const std::vector<uint8_t>& byteArray) {
    wxString result;

    for (const auto& byte : byteArray) {
        // Convert each byte to its two-digit hexadecimal representation and append to wxString
        result.append(wxString::Format(wxT("%02X-"), byte));
    }

    // Remove the last hyphen if the result is not empty
    if (!result.empty()) {
        result.RemoveLast();
    }

    return result;
}
void SavePacket(const std::string& filename, const u_char* packet, uint32_t size) {
    // Open the file for writing
    std::ifstream fileCheck(filename);
    if (!fileCheck.is_open()) {
        std::cout << "File does not exist. Creating the file." << std::endl;
    }
    else {
        std::cout << "File already exists. Appending data." << std::endl;
    }

    // Open the file for writing without resetting existing content
    std::fstream outFile(filename, std::ios::binary | std::ios::in | std::ios::out /* | std::ios::app*/);
    if (!outFile.is_open()) {
        std::cerr << "Error opening file for writing." << std::endl;
        return;
    }

    // Reserve 1 MB of data for packet pointer
    std::uint64_t fileSize = fs::file_size(filename);
    if (fileSize == 0) {
        const size_t megabyte = 1024 * 1024;
        // Fill the header with zeros
        std::vector<unsigned char> oneMegabyteVector(megabyte);
        std::memset(oneMegabyteVector.data(), 0, megabyte);

        outFile.write(reinterpret_cast<char*>(oneMegabyteVector.data()), megabyte);
    }

    
    std::uint64_t buffer = 0;
    outFile.seekg(0);
    outFile.read(reinterpret_cast<char*>(&buffer), sizeof(buffer));

    outFile.seekp(0);
    buffer += 1;
    outFile.write(reinterpret_cast<char*>(&buffer), sizeof(buffer));

    

    //The lenght of the array (at the moment it get the lenght of the pointer (4 Bytes))
    uint64_t sizeofpacket = size;

    if (buffer == 1) {
        outFile.seekp((buffer) * sizeof(buffer));
        uint64_t coordinate = sizeofpacket + (1024 * 1024);
        outFile.write(reinterpret_cast<char*>(&coordinate), sizeof(coordinate));
        outFile.seekp(coordinate);
    }
    else {
        uint64_t previousCoordinate = 0;
        outFile.seekg((buffer - 1) * sizeof(buffer));
        outFile.read(reinterpret_cast<char*>(&previousCoordinate), sizeof(previousCoordinate));
        uint64_t newCoordinate = previousCoordinate + sizeofpacket;
        outFile.seekp((buffer) * sizeof(buffer));
        outFile.write(reinterpret_cast<char*>(&newCoordinate), sizeof(newCoordinate));
        outFile.seekp(newCoordinate);
    }
    
    outFile.write(reinterpret_cast<char*>(&packet), sizeofpacket);

    

    // Write the size of the data as a uint64_t to the beginning of the file
    //outFile.seekp(0);
    //outFile.write(reinterpret_cast<char*>(&fileSize), sizeof(uint64_t));
    
    // Determine the position to write "FFDDFFDD" based on the file size
    //outFile.seekp(fileSize);

    // Write "FFDDFFDD" (hexadecimal) to the file
    //const std::vector<unsigned char> hexSequence = { 0xFF, 0xDD, 0xFF, 0xDD };
    //outFile.write(reinterpret_cast<const char*>(hexSequence.data()), hexSequence.size());

    // Close the file
    outFile.close();
}
