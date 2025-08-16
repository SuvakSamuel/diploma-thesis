Code I developed for the device to be able to communicate with the microcontroller acting as a hardware token. The communication is done over serial line (device and microcontroller are connected together using a wire capable of serial transfer).

The program serialCommApp was compiled using **gcc serialCommunicator.c utilProgram.c -o serialCommApp -lssl -lcrypto -ltss2-esys**. This means that the program requires the libraries *libssl-dev* and *libtss2-dev* to be installed on the system.
