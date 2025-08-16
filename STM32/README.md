The entire project I created in STM32CubeIDE. This project makes the microcontroller act as a hardware token. It communicates with the device it is connected to, and after succesful authentication, it provides the device with the second part of the master key needed for disk decryption.

All of the code I developed is contained in files:

serial/Core/Inc/commhandler.h

serial/Core/Src/main.c

serial/Core/Src/commhandler.c

serial/USB_DEVICE/usb_cdc_if.c
