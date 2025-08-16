These are the programs I developed for the device to be able to communicate with the microcontroller acting as a hardware token.

serialCommApp was compiled using the command **gcc serialCommunicator.c utilProgram.c -o serialCommApp -lssl -lcrypto -ltss2-esys**. This means that the program requires the libraries *libss-dev* and *libtss2-dev* to be installed on the system.
