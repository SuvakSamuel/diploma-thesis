#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "data_packet.h"
#include "utilProgram.h"

extern const unsigned char deviceCert[];
extern const uint16_t deviceCertLen;

int main() {
    int serial_port;
    struct termios tty;
    serial_port = open("/dev/ttyACM1", O_RDWR);  

    if (serial_port < 0) {
        perror("Chyba v seriovom porte");
        return 1;
    }
    
    if (tcgetattr(serial_port, &tty) != 0) {
        perror("Chyba pri ziskavani atributov serioveho portu");
        close(serial_port);
        return 1;
    }
    // baud rate
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);

    // flagy pre tty strukturu
    tty.c_cflag &= ~PARENB; // bez paritneho bitu
    tty.c_cflag &= ~CSTOPB; // jeden stop bit
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8; // 8 bitov na byte
    tty.c_cflag &= ~CRTSCTS; // vypni Hardware Flow Control
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // vypni Software Flow Control
    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // vypni special handling
    tty.c_lflag &= ~ICANON; // vypni kanonicky mod
    tty.c_lflag &= ~ECHO; // vypni echo
    tty.c_lflag &= ~ECHOE; // vypni erasure
    tty.c_lflag &= ~ECHONL; // vypni new-line echo
    tty.c_lflag &= ~ISIG; // vypni interpretaciu INTR, QUIT and SUSP
    tty.c_oflag = 0; // VYPNI POST-PROCESSING, SKURVENA PICOVINA MENILA \n NA KOKOTINY
    tty.c_cc[VTIME] = 255;

    // aplikujeme nastavenia
    if (tcsetattr(serial_port, TCSANOW, &tty) != 0) {
        perror("Chyba pri nastavovani atributov serioveho portu");
        close(serial_port);
        return 1;
    }
    // -----------------------------------------------------------------------------------------------------------------
    // urobim si a poslem prvu spravu
    MessageOne firstMessage = {{ 'H', 'e', 'l', 'o' }};
    ssize_t bytes_written = write(serial_port, firstMessage.initChars, sizeof(firstMessage.initChars));
    if (bytes_written < 0) {
        perror("Chyba pri pisani do serioveho portu");
        close(serial_port);
        return 1;
    }
    unsigned char returnSign = '\r';
    write(serial_port, &returnSign, 1);
    // -----------------------------------------------------------------------------------------------------------------
    // prijimam druhu spravu
    uint8_t receiveBuffer[64];
    memset(&receiveBuffer, 0, sizeof(receiveBuffer));
    MessageTwo secondMessage = {};
    // na strane tokenu sa implementoval kod co limituje velkost USB CDC paketu na 64 bytov
    // staci mat teda receiveBuffer velkosti 64 bytov
    // tento prvy read obsahuje data suvisiace s druhou spravou, velkostou spravy a velkostou certifikatu tokenu - 18 bytov
    ssize_t bytes_read = read(serial_port, receiveBuffer, sizeof(receiveBuffer));
    if (bytes_read < 0) {
        perror("Chyba pri citani zo serioveho portu");
    }
    // nasleduju veci ako odpoved dosky a jej ID
    for (int i = 0; i < 4; i++) {
        secondMessage.replyChars[i] = receiveBuffer[i];
        secondMessage.Tid_one[i] = receiveBuffer[i + 4];
        secondMessage.Tid_two[i] = receiveBuffer[i + 8];
        secondMessage.Tid_three[i] = receiveBuffer[i + 12];
    }
    // nasleduje dlzka certifikatu tokenu
    uint16_t tokenCertLen = (receiveBuffer[16] << 8) | receiveBuffer[17];
    // alokujem pamat
    uint8_t *tokenCert = malloc(tokenCertLen);
    if (tokenCert == NULL) {
        perror("malloc zlyhal");
        exit(1);
    }
    // zvysok uz je certifikat tokenu
    // tieto data vieme direktne kopirovat do pamati vyhradenej pre certifikat tokenu
    memcpy(tokenCert, receiveBuffer + 18, bytes_read - 18);
    size_t totalTokenRead = bytes_read - 18;
    while (totalTokenRead < tokenCertLen) {
        ssize_t n = read(serial_port, tokenCert + totalTokenRead, tokenCertLen - totalTokenRead);
        if (n < 0) {
            perror("Chyba pri citani zo serioveho portu");
            free(tokenCert);
            exit(1);
        }
        totalTokenRead += n;       
    }
    if (memcmp(firstMessage.initChars, secondMessage.replyChars, sizeof(secondMessage.replyChars)) != 0) {
		printf("Token sa neodzdravil spravne, zatvaram seriovy port.\n");
        close(serial_port);
        free(tokenCert);
        return 0;
	}
    if (verify_cert(tokenCert, tokenCertLen, "/home/user/certifikaty/CA.pem") != 1) 
    {
        printf("Neplatny certifikat, zatvaram seriovy port.\n");
        close(serial_port);
        free(tokenCert);
        return 0;
    }
    // -----------------------------------------------------------------------------------------------------------------
    // pripravim si tretiu spravu
    MessageThree thirdMessage = {};
    uint32_t epoch = time(NULL); 
    thirdMessage.timestamp[0] = (epoch & 0x000000ff);
	thirdMessage.timestamp[1] = (epoch & 0x0000ff00) >> 8;
	thirdMessage.timestamp[2] = (epoch & 0x00ff0000) >> 16;
	thirdMessage.timestamp[3] = (epoch & 0xff000000) >> 24;
	// session key aj IV nahodne generujeme z /dev/urandom, TENTO JE PRE STVRTU, PIATU A SIESTU SPRAVU
    urandom_random_bytes(thirdMessage.session_key);
    urandom_random_bytes(thirdMessage.session_IV);
    // ID tokenu tentokrat staci len skopirovat
    for (int i = 0; i < 4; i++) {
        thirdMessage.Tid_one[i] = secondMessage.Tid_one[i];
        thirdMessage.Tid_two[i] = secondMessage.Tid_two[i];
        thirdMessage.Tid_three[i] = secondMessage.Tid_three[i];
    }
    // nakoniec ID zariadenia - z NV indexov TPM, potrebne je sudo
    /*char* hash = nvread();*/
    char* hash = "876f88001a970a5171e27688a276ff71";
    // XORneme tento hash
    for (int i = 0; i < 8; i++) {
        thirdMessage.PC_id[i] = hash[i] ^ hash[i + 8];
    }
    // sifrujeme a odosielame tretiu spravu. najprv verejny kluc extrahujme
    EVP_PKEY *pubkey = extract_pubkey(tokenCert, tokenCertLen);
    // data v MessageThree strukture dajme do buffra a vyplnme nulami na velkost 512 bitov
    unsigned char paddedPlaintext[512] = {0};
    memcpy(paddedPlaintext, &thirdMessage, sizeof(thirdMessage));
    // AES sifrovanie tohto buffra, 128-bit velkost bloku, TIETO HODNOTY PLATIA IBA PRE TRETIU SPRAVU
    unsigned char msgthree_aes_key[16];  // 128-bit AES kluc
    unsigned char msgthree_iv[16];       // 128-bit IV (inicializacny vektor)
    urandom_random_bytes(msgthree_aes_key);
    urandom_random_bytes(msgthree_iv);
    unsigned char encrypted[512];
    int encryptedLen = 0;
    aes_encrypt(paddedPlaintext, 512, msgthree_aes_key, msgthree_iv, encrypted, &encryptedLen);
    // zasifrujme AES kluc a IV verejnym klucom tokenu, tym padom iba token bude moct desifrovat povodnu spravu
    unsigned char encryptedKey[256]; // velkost RSA kluca v bytoch (2048bit)
    size_t encryptedKeyLen = sizeof(encryptedKey);
    unsigned char encryptedIV[256]; 
    size_t encryptedIVLen = sizeof(encryptedIV);
    encrypt_with_pubkey(pubkey, msgthree_aes_key, sizeof(msgthree_aes_key), encryptedKey, &encryptedKeyLen);
    encrypt_with_pubkey(pubkey, msgthree_iv, sizeof(msgthree_iv), encryptedIV, &encryptedIVLen);
    EVP_PKEY_free(pubkey); // mozme uz uvolnit lebo iba raz pouzivame tento verejny kluc na sifrovanie
    free(tokenCert);
    // nakoniec to cele hodime do jedneho buffera spolu s certifikatom PC a odosleme to doske
    size_t transmitBufferLen = 1024 + deviceCertLen;
    uint8_t *transmitBuffer = malloc(transmitBufferLen);
    if (transmitBuffer == NULL) {
        perror("malloc zlyhal");
        exit(1);
    }
    memcpy(transmitBuffer, encryptedKey, encryptedKeyLen);
    memcpy(transmitBuffer + 256, encryptedIV, encryptedIVLen);
    memcpy(transmitBuffer + 512, encrypted, encryptedLen);
    memcpy(transmitBuffer + 1024, deviceCert, deviceCertLen);
    
    size_t bytes_sent = 0;
    while (bytes_sent < transmitBufferLen) {
        size_t remaining = transmitBufferLen - bytes_sent;
        size_t to_send = (remaining > 64) ? 64 : remaining;

        ssize_t result = write(serial_port, transmitBuffer + bytes_sent, to_send);
        if (result < 0) {
            perror("Write failed");
            free(transmitBuffer);
            return 1;
        }

        bytes_sent += result;
        usleep(1000); // 1 ms
    }
    write(serial_port, &returnSign, 1);
    free(transmitBuffer);
    // -----------------------------------------------------------------------------------------------------------------
    // prijimam stvrtu spravu
    MessageFour fourthMessage = {};
    uint8_t* incomingMessage = malloc(512);
    size_t totalRead = 0;
    while (totalRead < 512) {
        ssize_t n = read(serial_port, incomingMessage + totalRead, 512 - totalRead);
        if (n < 0) {
            perror("Chyba pri citani zo serioveho portu");
            free(incomingMessage);
            exit(1);
        }
        totalRead += n;       
    }
    uint8_t decryptedPayload[512];
    int decryptedLen;
    aes_decrypt(incomingMessage, 512, thirdMessage.session_key, thirdMessage.session_IV, decryptedPayload, &decryptedLen);
    free(incomingMessage);
    memcpy(fourthMessage.timestamp, &decryptedPayload[0], 4);
    memcpy(fourthMessage.Tid_one, &decryptedPayload[4], 4);
    memcpy(fourthMessage.Tid_two, &decryptedPayload[8], 4);
    memcpy(fourthMessage.Tid_three, &decryptedPayload[12], 4);
    memcpy(fourthMessage.PC_id, &decryptedPayload[16], 8);
    memcpy(fourthMessage.T_nonce, &decryptedPayload[24], 16);
    // kontrolujem token id a PC id ci su rovnake
    if(memcmp(thirdMessage.Tid_one, fourthMessage.Tid_one, sizeof(thirdMessage.Tid_one)) != 0 ||
			memcmp(thirdMessage.Tid_two, fourthMessage.Tid_two, sizeof(thirdMessage.Tid_two)) != 0 ||
					memcmp(thirdMessage.Tid_three, fourthMessage.Tid_three, sizeof(thirdMessage.Tid_three)) != 0) {
                        close(serial_port);
			            return -1;
	}
    if(memcmp(thirdMessage.PC_id, fourthMessage.PC_id, sizeof(thirdMessage.PC_id)) != 0) {
        close(serial_port);
		return -1;
    }
    
    // -----------------------------------------------------------------------------------------------------------------
    // pripravim si piatu spravu
    MessageFive fifthMessage = {};
    uint32_t recTimestamp = (fourthMessage.timestamp[3] << 24) | (fourthMessage.timestamp[2] << 16) |
	     ( fourthMessage.timestamp[1] << 8 ) | (fourthMessage.timestamp[0]);
	recTimestamp += 1;
    fifthMessage.timestamp[0] = (recTimestamp & 0x000000ff);
	fifthMessage.timestamp[1] = (recTimestamp & 0x0000ff00) >> 8;
	fifthMessage.timestamp[2] = (recTimestamp & 0x00ff0000) >> 16;
	fifthMessage.timestamp[3] = (recTimestamp & 0xff000000) >> 24;
	memcpy(fifthMessage.Tid_one, thirdMessage.Tid_one, 4);
	memcpy(fifthMessage.Tid_two, thirdMessage.Tid_two, 4);
	memcpy(fifthMessage.Tid_three, thirdMessage.Tid_three, 4);
	memcpy(fifthMessage.PC_id, thirdMessage.PC_id, 8);
    memcpy(fifthMessage.T_nonce, fourthMessage.T_nonce, 16);

    // najprv zasifrujeme tuto piatu spravu; resetujme vopred definovane polia ako paddedPlaintext a encrypted
    memset(&paddedPlaintext, 0, sizeof(paddedPlaintext));
    memcpy(paddedPlaintext, &fifthMessage, sizeof(fifthMessage));
    memset(&encrypted, 0, sizeof(encrypted));
    encryptedLen = 0;
    aes_encrypt(paddedPlaintext, 512, thirdMessage.session_key, thirdMessage.session_IV, encrypted, &encryptedLen);

    // vygenerujme SHA-256 hash z tejto spravy
    uint8_t msgFiveHash[SHA256_DIGEST_LENGTH]; // 32 bytov, konstanta od OpenSSL
    SHA256((const unsigned char*)&fifthMessage, sizeof(MessageFive), msgFiveHash); // metoda od OpenSSL

    // podpisme hash sukromnym klucom zariadenia
    BIO *bio = BIO_new_file("/home/user/certifikaty/device.key", "r");
    EVP_PKEY *privkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    uint8_t *sigHash = NULL;
    size_t sigHashLen = 0; // to bude 256 bytov
    sign_sha256_hash(msgFiveHash, privkey, &sigHash, &sigHashLen);

    // veci napratajme do buffera na odoslanie a odoslime
    size_t msgFiveTransmitBufferLen = 800; // 512 + 256 + 32
    uint8_t* msgFiveTransmitBuffer = malloc(msgFiveTransmitBufferLen);
    memcpy(msgFiveTransmitBuffer, encrypted, encryptedLen);
    memcpy(msgFiveTransmitBuffer + 512, sigHash, sigHashLen);
    memcpy(msgFiveTransmitBuffer + 768, msgFiveHash, sizeof(msgFiveHash));
    bytes_sent = 0;
    while (bytes_sent < msgFiveTransmitBufferLen) {
        size_t remaining = msgFiveTransmitBufferLen - bytes_sent;
        size_t to_send = (remaining > 64) ? 64 : remaining;

        ssize_t result = write(serial_port, msgFiveTransmitBuffer + bytes_sent, to_send);
        if (result < 0) {
            perror("Write failed");
            free(msgFiveTransmitBuffer);
            return 1;
        }

        bytes_sent += result;
        usleep(1000); // 1 ms
    }
    write(serial_port, &returnSign, 1);
    free(msgFiveTransmitBuffer);
    // -----------------------------------------------------------------------------------------------------------------
    // prijimam siestu, poslednu spravu
    MessageSix sixthMessage = {};
    uint8_t* incomingFinalMessage = malloc(512);
    totalRead = 0;
    while (totalRead < 512) {
        ssize_t n = read(serial_port, incomingFinalMessage + totalRead, 512 - totalRead);
        if (n < 0) {
            perror("Chyba pri citani zo serioveho portu");
            free(incomingFinalMessage);
            exit(1);
        }
        totalRead += n;       
    }
    memset(&decryptedPayload, 0, sizeof(decryptedPayload));
    decryptedLen = 0;
    aes_decrypt(incomingFinalMessage, 512, thirdMessage.session_key, thirdMessage.session_IV, decryptedPayload, &decryptedLen);
    free(incomingFinalMessage);
    memcpy(sixthMessage.timestamp, &decryptedPayload[0], 4);
    memcpy(sixthMessage.Tid_one, &decryptedPayload[4], 4);
    memcpy(sixthMessage.Tid_two, &decryptedPayload[8], 4);
    memcpy(sixthMessage.Tid_three, &decryptedPayload[12], 4);
    memcpy(sixthMessage.PC_id, &decryptedPayload[16], 8);
    memcpy(sixthMessage.key, &decryptedPayload[24], 64);
    // kontrolujem token id a PC id ci su rovnake, a ci prijaty timestamp je (povodny timestamp + 3)
    if(memcmp(thirdMessage.Tid_one, fourthMessage.Tid_one, sizeof(thirdMessage.Tid_one)) != 0 ||
			memcmp(thirdMessage.Tid_two, fourthMessage.Tid_two, sizeof(thirdMessage.Tid_two)) != 0 ||
					memcmp(thirdMessage.Tid_three, fourthMessage.Tid_three, sizeof(thirdMessage.Tid_three)) != 0) {
                        close(serial_port);
			            return -1;
	}
    if(memcmp(thirdMessage.PC_id, fourthMessage.PC_id, sizeof(thirdMessage.PC_id)) != 0) {
        close(serial_port);
		return -1;
    }
    uint32_t finalTimestamp = (sixthMessage.timestamp[3] << 24) | (sixthMessage.timestamp[2] << 16) |
	     ( sixthMessage.timestamp[1] << 8 ) | (sixthMessage.timestamp[0]);
    if (finalTimestamp != (epoch+3))
    {
        close(serial_port);
		return -1;
    }
    // vypis ziskanu druhu cast kluca, ked sa to spusti v shell skripte tak sa to zachyti na spracovanie
    char keyString[65];             // +1 pre null-terminator
    memcpy(keyString, sixthMessage.key, 64);
    keyString[64] = '\0';           // null-terminator
    printf("%s\n", keyString); 
    // zavri seriovy port a konci main, komunikacia s tokenom skoncila
    close(serial_port);
    return 0;
}
