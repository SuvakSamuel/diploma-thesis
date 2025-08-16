#include "main.h"
#include "commhandler.h"
#include "usbd_cdc_if.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

extern uint8_t sendBuffer[2500];
extern uint16_t sendCounter;
extern const unsigned char tokenCert[];
extern const uint16_t tokenCertLen;
extern const unsigned char tokenPrivKey[];
extern const uint16_t tokenPrivKeyLen;
extern const unsigned char CACert[];
extern const uint16_t CACertLen;
RsaKey pubKey;

MessageOne firstMessage = {{'a','a','a','a'}};
MessageTwo secondMessage = {{'H','e','l','o'},{0},{0},{0}};
MessageThree thirdMessage = {{0},{0},{0},{0},{0},{0},{0}};
MessageFour fourthMessage = {{0},{0},{0},{0},{0}};
MessageFive fifthMessage = {{0},{0},{0},{0},{0}};
MessageSix sixthMessage = {{0},{0},{0},{0},{0},{0}};

/*void setMessageStructs() {
	firstMessage = (MessageOne){{'a','a','a','a'}};
	secondMessage = (MessageTwo){{'H','e','l','o'},{0},{0},{0}};
	thirdMessage = (MessageThree){{0},{0},{0},{0},{0},{0},{0}};
	fourthMessage = (MessageFour){{0},{0},{0},{0},{0}};
	fifthMessage = (MessageFive){{0},{0},{0},{0},{0}};
	sixthMessage = (MessageSix){{0},{0},{0},{0},{0},{0}};
}*/
void firstMessageHandler(uint8_t* receivedChars) {
	for (int i = 0; i < 4; i++) {
		firstMessage.initChars[i] = receivedChars[i];
	}
	// skontroluj ci sme v prvej sprave dostali uvodne znaky 'H' 'e' 'l' 'o'.
	// treba dorobit odpoved v pripade ze sme nedostali taketo znaky.
	// v podstate celemu projektu treba dorobit vratenie chyboveho kodu v pripade ze nieco zlyha.
	if(memcmp(firstMessage.initChars, secondMessage.replyChars, sizeof(secondMessage.replyChars)) == 0) {
		secondMessageSender();
	}
}

void secondMessageSender() {
	// vrat device ID co je rozdelene do troch 32bit hodnot
	uint32_t uid_one = HAL_GetUIDw0();
	uint32_t uid_two = HAL_GetUIDw1();
	uint32_t uid_three = HAL_GetUIDw2();

	// vsetko nasekaj do sendBuffera
	memcpy(sendBuffer, secondMessage.replyChars, 4);
	sendCounter += 4;
	for (size_t i = 0; i < 3; i++)
	{
		uint8_t UIDsplit[4];
		if (i == 0) {
			UIDsplit[0] = (uid_one & 0x000000ff);
			UIDsplit[1] = (uid_one & 0x0000ff00) >> 8;
			UIDsplit[2] = (uid_one & 0x00ff0000) >> 16;
			UIDsplit[3] = (uid_one & 0xff000000) >> 24;
			memcpy(secondMessage.Tid_one, UIDsplit, 4);
		} else if (i == 1) {
			UIDsplit[0] = (uid_two & 0x000000ff);
			UIDsplit[1] = (uid_two & 0x0000ff00) >> 8;
			UIDsplit[2] = (uid_two & 0x00ff0000) >> 16;
			UIDsplit[3] = (uid_two & 0xff000000) >> 24;
			memcpy(secondMessage.Tid_two, UIDsplit, 4);
		} else {
			UIDsplit[0] = (uid_three & 0x000000ff);
			UIDsplit[1] = (uid_three & 0x0000ff00) >> 8;
			UIDsplit[2] = (uid_three & 0x00ff0000) >> 16;
			UIDsplit[3] = (uid_three & 0xff000000) >> 24;
			memcpy(secondMessage.Tid_three, UIDsplit, 4);
		}
		memcpy(sendBuffer + sendCounter, UIDsplit, 4);
		sendCounter += 4;
	}

	// treba este vlozit velkost certifikatu tokenu pred samotny certifikat
	// velkost je ale vyssia ako 256, treba ju splitnut na uint8_t
	sendBuffer[sendCounter] = (tokenCertLen >> 8) & 0xFF;
	sendCounter++;
	sendBuffer[sendCounter] = tokenCertLen  & 0xFF;
	sendCounter++;
	// vkladam uz certifikat tokenu
	memcpy(sendBuffer + sendCounter, tokenCert, tokenCertLen);
	sendCounter += tokenCertLen;
	return;
}

void thirdMessageHandler(uint8_t* encryptedKey, uint8_t* encryptedIV, uint8_t* payload, uint8_t* deviceCertBuffer, uint16_t deviceCertLen) {
	// over certifikat zariadenia ci je podpisany CA
	WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (wolfSSL_CTX_load_verify_buffer(ctx, CACert, CACertLen, WOLFSSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        return;
    }
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    if (!cm) {
        return;
    }
    int ret = wolfSSL_CertManagerVerifyBuffer(cm, deviceCertBuffer, deviceCertLen, WOLFSSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        return;
    }

    // ak ano, tak extrahuj z neho verejny kluc
    wc_InitRsaKey(&pubKey, NULL);
    DecodedCert extractedPCCert;
    InitDecodedCert(&extractedPCCert, (byte*)deviceCertBuffer, deviceCertLen, NULL);
    ret = ParseCert(&extractedPCCert, CERT_TYPE, NO_VERIFY, NULL);
    word32 idx = 0;
    ret = wc_RsaPublicKeyDecode(extractedPCCert.publicKey, &idx, &pubKey, extractedPCCert.pubKeySize);
    if (ret != 0) {
        wolfSSL_CertManagerFree(cm);
        wolfSSL_CTX_free(ctx);
        return;
    }
    wolfSSL_CertManagerFree(cm);
    wolfSSL_CTX_free(ctx);

    // ak ano tak mozeme desifrovat prijate data. zober sukromny kluc tokenu
    RsaKey rsaKey;
    WC_RNG rng;
    int rsaRet = wc_InitRsaKey(&rsaKey, NULL);
    if (rsaRet != 0) {
        return;
    }
    rsaRet = wc_InitRng(&rng);
    if (rsaRet != 0) {
        wc_FreeRsaKey(&rsaKey);
        return;
    }
    idx = 0;
    rsaRet = wc_RsaPrivateKeyDecode(tokenPrivKey, &idx, &rsaKey, tokenPrivKeyLen);
    if (rsaRet != 0) {
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return;
    }
    wc_RsaSetRNG(&rsaKey, &rng);

    // desifrujeme
    uint8_t decryptedKey[256] = {0};
    word32 decryptedKeyLen = sizeof(decryptedKey);
    uint8_t decryptedIV[256] = {0};
    word32 decryptedIVLen = sizeof(decryptedIV);
    word32 inputSize = 256;
    // najprv kluc od celej spravy, sukromnym klucom tokenu
    rsaRet = wc_RsaPrivateDecrypt(encryptedKey, inputSize, decryptedKey, decryptedKeyLen, &rsaKey);
    // potom inicializacny vektor, sukromnym klucom tokenu
    rsaRet = wc_RsaPrivateDecrypt(encryptedIV, inputSize, decryptedIV, decryptedIVLen, &rsaKey);
    // a nakoniec celu spravu (payload)
    Aes aes;
    int aesRet = wc_AesSetKey(&aes, decryptedKey, 16, decryptedIV, AES_DECRYPTION);
    if (aesRet != 0) {
        return;
    }
    uint8_t decryptedPayload[512];
    aesRet = wc_AesCbcDecrypt(&aes, decryptedPayload, payload, 512);
    if (aesRet != 0) {
        return;
    }

    // ukladanie dat do struktury
    memcpy(thirdMessage.timestamp, &decryptedPayload[0], 4);
    memcpy(thirdMessage.session_key, &decryptedPayload[4], 16);
    memcpy(thirdMessage.session_IV, &decryptedPayload[20], 16);
    memcpy(thirdMessage.Tid_one, &decryptedPayload[36], 4);
    memcpy(thirdMessage.Tid_two, &decryptedPayload[40], 4);
    memcpy(thirdMessage.Tid_three, &decryptedPayload[44], 4);
    memcpy(thirdMessage.PC_id, &decryptedPayload[48], 8);
    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);
    wc_AesFree(&aes);

    // skontrolujme este ci prijaty token ID suladi s tym co sme odoslali v druhej sprave
    if(memcmp(secondMessage.Tid_one, thirdMessage.Tid_one, sizeof(secondMessage.Tid_one)) != 0 ||
    		memcmp(secondMessage.Tid_two, thirdMessage.Tid_two, sizeof(secondMessage.Tid_two)) != 0 ||
    				memcmp(secondMessage.Tid_three, thirdMessage.Tid_three, sizeof(secondMessage.Tid_three)) != 0) {
    	return;
    }
	fourthMessageSender();
}

void fourthMessageSender() {
	// inkrementujme timestamp o 1
	uint32_t timestamp = (thirdMessage.timestamp[3] << 24) | (thirdMessage.timestamp[2] << 16) |
	     ( thirdMessage.timestamp[1] << 8 ) | (thirdMessage.timestamp[0]);
	timestamp += 1;

	// pripravme si  takmer celu stvrtu spravu podla struktury MessageFour
	fourthMessage.timestamp[0] = (timestamp & 0x000000ff);
	fourthMessage.timestamp[1] = (timestamp & 0x0000ff00) >> 8;
	fourthMessage.timestamp[2] = (timestamp & 0x00ff0000) >> 16;
	fourthMessage.timestamp[3] = (timestamp & 0xff000000) >> 24;
	memcpy(fourthMessage.Tid_one, thirdMessage.Tid_one, 4);
	memcpy(fourthMessage.Tid_two, thirdMessage.Tid_two, 4);
	memcpy(fourthMessage.Tid_three, thirdMessage.Tid_three, 4);
	memcpy(fourthMessage.PC_id, thirdMessage.PC_id, 8);

	// este vygenerujme nonce
	uint8_t randomBytes[16];
	WC_RNG rng;
	if (wc_InitRng(&rng) != 0) {
	    return;
	}
	if (wc_RNG_GenerateBlock(&rng, randomBytes, sizeof(randomBytes)) != 0) {
	    wc_FreeRng(&rng);
	    return;
	}
	wc_FreeRng(&rng);
	memcpy(fourthMessage.T_nonce, randomBytes, 16);

	// nasledne zasifrujme spravu cez sessionKey
	unsigned char paddedPlaintext[512] = {0};
	memcpy(paddedPlaintext, &fourthMessage, sizeof(fourthMessage));
	Aes aes;
	int aesRet = wc_AesSetKey(&aes, thirdMessage.session_key, 16, thirdMessage.session_IV, AES_ENCRYPTION);
	if (aesRet != 0) {
	    return;
	}
	uint8_t encryptedPayload[512];
	aesRet = wc_AesCbcEncrypt(&aes, encryptedPayload, paddedPlaintext, 512);
	if (aesRet != 0) {
	    return;
	}

	// a potom vlozme ju do sendBuffer na odoslanie
	memcpy(sendBuffer, encryptedPayload, 512);
	sendCounter = 512;
	wc_AesFree(&aes);
	return;
}

void fifthMessageHandler(uint8_t* payload, uint8_t* sigHash) {
	// AES desifrovanie payload a ulozenie do struktury
	Aes aes;
	int aesRet = wc_AesSetKey(&aes, thirdMessage.session_key, 16, thirdMessage.session_IV, AES_DECRYPTION);
	if (aesRet != 0) {
	    return;
	}
	uint8_t decryptedPayload[512];
	aesRet = wc_AesCbcDecrypt(&aes, decryptedPayload, payload, 512);
	if (aesRet != 0) {
	    return;
	}
	memcpy(fifthMessage.timestamp, &decryptedPayload[0], 4);
	memcpy(fifthMessage.Tid_one, &decryptedPayload[4], 4);
	memcpy(fifthMessage.Tid_two, &decryptedPayload[8], 4);
	memcpy(fifthMessage.Tid_three, &decryptedPayload[12], 4);
	memcpy(fifthMessage.PC_id, &decryptedPayload[16], 8);
	memcpy(fifthMessage.T_nonce, &decryptedPayload[24], 16);
	wc_AesFree(&aes);

	// teraz vytvorme SHA256 hash z prijatej piatej spravy
	Sha256 sha;
	uint8_t genHash[SHA256_DIGEST_SIZE];
	int hashRet = wc_InitSha256(&sha);
	hashRet = wc_Sha256Update(&sha, (const uint8_t*)&fifthMessage, sizeof(MessageFive));
	hashRet = wc_Sha256Final(&sha, genHash);

	// kontrolujme token id, PC id a nonce ci su rovnake
	if(memcmp(fifthMessage.Tid_one, fourthMessage.Tid_one, sizeof(fourthMessage.Tid_one)) != 0 ||
			memcmp(fifthMessage.Tid_two, fourthMessage.Tid_two, sizeof(fourthMessage.Tid_two)) != 0 ||
					memcmp(fifthMessage.Tid_three, fourthMessage.Tid_three, sizeof(fourthMessage.Tid_three)) != 0) {
		return;
	}
	if(memcmp(fifthMessage.PC_id, fourthMessage.PC_id, sizeof(fourthMessage.PC_id)) != 0) {
	    return;
	}
	if(memcmp(fifthMessage.T_nonce, fourthMessage.T_nonce, sizeof(fourthMessage.T_nonce)) != 0) {
		    return;
	}

	// ak ano, tak overme este, ci prijaty podpisany hash je podpisany vypoctovym zariadenim
	// teda pouzije sa vygenerovany hash a verejny kluc zariadenia na porovnanie s prijatym podpisanym hashom
	hashRet = wc_SignatureVerifyHash(
			WC_HASH_TYPE_SHA256, 		// typ hashu SHA256
			WC_SIGNATURE_TYPE_RSA, 		// typ podpisu RSA
			genHash, 32, 				// hash vytvoreny z prijatych dat
			sigHash, 256, 				// hash co podpisalo zariadenie
			&pubKey, sizeof(RsaKey)		// verejny kluc zariadenia
				);
	if(hashRet == 0) {
		sixthMessageSender();
	}
}

void sixthMessageSender() {
	// inkrementujme timestamp o 1
	uint32_t timestamp = (fifthMessage.timestamp[3] << 24) | (fifthMessage.timestamp[2] << 16) |
		     ( fifthMessage.timestamp[1] << 8 ) | (fifthMessage.timestamp[0]);
	timestamp += 1;

	// pripravme si takmer celu siestu spravu podla struktury MessageSix
	sixthMessage.timestamp[0] = (timestamp & 0x000000ff);
	sixthMessage.timestamp[1] = (timestamp & 0x0000ff00) >> 8;
	sixthMessage.timestamp[2] = (timestamp & 0x00ff0000) >> 16;
	sixthMessage.timestamp[3] = (timestamp & 0xff000000) >> 24;
	memcpy(sixthMessage.Tid_one, fifthMessage.Tid_one, 4);
	memcpy(sixthMessage.Tid_two, fifthMessage.Tid_two, 4);
	memcpy(sixthMessage.Tid_three, fifthMessage.Tid_three, 4);
	memcpy(sixthMessage.PC_id, fifthMessage.PC_id, 8);

	// treba este vlozit druhu cast hlavneho kluca, na tu vsak potrebujeme interakciu s tlacidlom na tokene
	GPIO_InitTypeDef gpioLed = {0};
	gpioLed.Pin = GPIO_PIN_12;
	gpioLed.Mode = GPIO_MODE_OUTPUT_PP;
	gpioLed.Pull = GPIO_NOPULL;
	gpioLed.Speed = GPIO_SPEED_FREQ_LOW;
	HAL_GPIO_Init(GPIOD, &gpioLed);

	GPIO_InitTypeDef gpioBtn = {0};
	gpioBtn.Pin = GPIO_PIN_0;
	gpioBtn.Mode = GPIO_MODE_INPUT;
	gpioBtn.Pull = GPIO_NOPULL;
	HAL_GPIO_Init(GPIOA, &gpioBtn);

	HAL_GPIO_WritePin(GPIOD, GPIO_PIN_12, GPIO_PIN_SET);
	while (HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_RESET) {
	    // cakame kym sa stlaci tlacidlo
	}
	const char *predefinedHash = "3d9cf246585e2e116a9a4407ebd7d8dffea0dfa934a515dbe5cd6657aac7c222";
	memcpy(sixthMessage.key, predefinedHash, 64);
	HAL_GPIO_WritePin(GPIOD, GPIO_PIN_12, GPIO_PIN_RESET);

	// nasledne zasifrujme celu spravu cez sessionKey
	unsigned char paddedPlaintext[512] = {0};
	memcpy(paddedPlaintext, &sixthMessage, sizeof(sixthMessage));
	Aes aes;
	int aesRet = wc_AesSetKey(&aes, thirdMessage.session_key, 16, thirdMessage.session_IV, AES_ENCRYPTION);
	if (aesRet != 0) {
		return;
	}
	uint8_t encryptedPayload[512];
	aesRet = wc_AesCbcEncrypt(&aes, encryptedPayload, paddedPlaintext, 512);
	if (aesRet != 0) {
		return;
	}

	// a potom vlozme ju do sendBuffer na odoslanie
	memcpy(sendBuffer, encryptedPayload, 512);
	sendCounter = 512;
	wc_AesFree(&aes);
	return;
}
