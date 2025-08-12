#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_esys.h>

#define NV_INDEX 0x1410010
#define NV_SIZE 64

int main() {
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;

    rc = Esys_Initialize(&ectx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys inicializacia zlyhala: 0x%x\n", rc);
        return 1;
    }

    ESYS_TR authHandle = ESYS_TR_RH_OWNER;
    ESYS_TR nvHandle;

    rc = Esys_TR_FromTPMPublic(ectx, NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys TR_FromTPMPublic zlyhal: 0x%x\n", rc);
        Esys_Finalize(&ectx);
        return 1;
    }

    TPM2B_MAX_NV_BUFFER *nvData;
    rc = Esys_NV_Read(ectx,authHandle,nvHandle,ESYS_TR_PASSWORD,ESYS_TR_NONE,ESYS_TR_NONE,NV_SIZE,0,&nvData);

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys NV_Read zlyhal: 0x%x\n", rc);
        Esys_Finalize(&ectx);
        return 1;
    }

    char *nvString = malloc(nvData->size + 1);
    if (!nvString) {
        fprintf(stderr, "malloc pre string zlyhal\n");
        Esys_Free(nvData);
        Esys_Finalize(&ectx);
        return 1;
    }
    memcpy(nvString, nvData->buffer, nvData->size);
    nvString[nvData->size] = '\0'; // null zakoncenie
    printf(nvString);

    Esys_Free(nvData);
    Esys_Finalize(&ectx);
    return 0;
}