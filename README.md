# NoCifraras

Video in Youtube: https://youtu.be/6Zo52E0Avm4

I developed this project as a final work of the Masters degree in Reversing and Malware analysis. I successfully detonated 369 samples of ransomware from 38 different ransomware families, studied the results and developed an application - named NoCifraras - programmed in C and C++ to stop ransomware.

One of the conclusions of this project is that most ransomware applications, 92% of the thirty-eight ransomware families included in this study, use the old Cryptographic API function CryptEncrypt, whilst legitimate software do not. This was leveraged to make the developed tool NoCifraras highly successful in shutting down the 92% of ransomware applications right from the start. 

The application is contains three modules: a monitor of process monitor; a DLL injector; and a DLL to be injected into processes and monitor them internally for Windows API calls.

DISCLAIMER: Use this tool at your own risk. The creator of NoCifraras is not responsible for any damage related to any kind of use of this tool.
DISCLAIMER 2: The code is not the more elegant and needs to be optimized for memory use.
