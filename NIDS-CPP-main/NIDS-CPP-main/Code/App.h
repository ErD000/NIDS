#ifndef APP_H
#define APP_H

#include "NIDSFrame.h" // Include the NIDSFrame header


// Declare the custom event type using the wxDECLARE_EVENT macro.
//useless ??? :
//wxDECLARE_EVENT(wxEVT_CUSTOM_TEXT_APPEND, wxCommandEvent);

class NIDSApp : public wxApp {
public:
    virtual bool OnInit();
};

#endif // APP_H
