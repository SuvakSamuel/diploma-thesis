#ifndef DATA_PACKET_H
#define DATA_PACKET_H

#include <stdint.h>

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

#endif // DATA_PACKET_H