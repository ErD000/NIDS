## NIDS-C++:
 	...

## Setup NEW:
 * Visual Studio 2022:
   - [Télécharger Visual Studio 2022](https://visualstudio.microsoft.com/fr/) (Lors de l'installation bien choisir les options avec c++ !!!)
   - [Télécharger framework WxWidget](https://www.wxwidgets.org/downloads/)
   - [Instruction d'installation](https://www.youtube.com/watch?v=1fZL13jIbFQ)
   - NPCAP:
      - [NPCAP installer](https://npcap.com/dist/npcap-1.78.exe)
      - [NPCAP .ZIP](https://npcap.com/dist/npcap-sdk-1.13.zip) ajouter le lib et include qui sont dans le .zip (demander à erwin)
      - Intégrez le dans Visual Studio 2022 (demander à erwin)
   - Ouvrir Visual Studio 2022, et essayer de [compiler le code suivant](https://github.com/PSR-J0740/NIDS-CPP/blob/main/BuildMe.cpp)
## Setup (Ubuntu/Debian):
 * `apt-get install cmake` 
 * `apt-get install libwxgtk-media3.0-gtk3-dev`
 * Cloner la branche puis: 
   * `mkdir build`
   * `cd build`
   * `cmake ..`
   * `make`
   * `./main`