#ifndef CUSTOM_EVENTS_H
#define CUSTOM_EVENTS_H

#include <wx/event.h>

// Declare the custom event type using the wxDECLARE_EVENT macro.
wxDECLARE_EVENT(wxEVT_CUSTOM_TEXT_APPEND, wxCommandEvent);

// Custom event identifiers
enum {
    ID_TEXT_APPEND_EVENT = wxID_HIGHEST + 1 // Ensure this ID is unique
};

#endif // CUSTOM_EVENTS_H

