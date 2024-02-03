#include "App.h"
#include "NIDSFrame.h"
#include "CustomEvents.h"

wxIMPLEMENT_APP(NIDSApp);

//Main
bool NIDSApp::OnInit() {
    NIDSFrame* frame = new NIDSFrame("NIDS Interface", wxPoint(50, 50), wxSize(1600, 800));
    frame->Show(true);
    return true;
}
