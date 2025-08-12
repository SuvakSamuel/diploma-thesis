#ifndef COMMHANDLER_H
#define COMMHANDLER_H

typedef struct {
    char initChars[4];
} MessageOne;

typedef struct {
	char replyChars[4];
	uint8_t Tid_one[4];
	uint8_t Tid_two[4];
	uint8_t Tid_three[4];
} MessageTwo;

typedef struct {
	uint8_t timestamp[4];
	uint8_t session_key[16];
	uint8_t session_IV[16];
	uint8_t Tid_one[4];
	uint8_t Tid_two[4];
	uint8_t Tid_three[4];
	uint8_t PC_id[8];
} MessageThree;

typedef struct {
	uint8_t timestamp[4];
	uint8_t Tid_one[4];
	uint8_t Tid_two[4];
	uint8_t Tid_three[4];
	uint8_t PC_id[8];
	uint8_t T_nonce[16];
} MessageFour;

typedef struct {
	uint8_t timestamp[4];
	uint8_t Tid_one[4];
	uint8_t Tid_two[4];
	uint8_t Tid_three[4];
	uint8_t PC_id[8];
	uint8_t T_nonce[16];
} MessageFive;

typedef struct {
	uint8_t timestamp[4];
	uint8_t Tid_one[4];
	uint8_t Tid_two[4];
	uint8_t Tid_three[4];
	uint8_t PC_id[8];
	char key[64];
} MessageSix;

//void setMessageStructs();
void firstMessageHandler(uint8_t* receivedChars);
void secondMessageSender();
void thirdMessageHandler(uint8_t* encryptedKey, uint8_t* encryptedIV, uint8_t* payload, uint8_t* deviceCertBuffer, uint16_t deviceCertLen);
void fourthMessageSender();
void fifthMessageHandler(uint8_t* payload, uint8_t* sigHash, uint8_t* hash);
void sixthMessageSender();

#endif // COMMHANDLER_H
