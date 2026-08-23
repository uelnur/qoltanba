#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "KalkanCrypt.h"
#include "shim.h"

static void *g_handle = NULL;
static stKCFunctionsType *kc = NULL;

unsigned long probe_load(const char *libpath, char *errbuf, int *errlen) {
    g_handle = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
    if (!g_handle) {
        const char *e = dlerror();
        if (errbuf && errlen) { int n = snprintf(errbuf, *errlen, "dlopen: %s", e ? e : "?"); *errlen = n; }
        return 1;
    }
    typedef int (*getlist_t)(stKCFunctionsType **);
    getlist_t gl = (getlist_t)dlsym(g_handle, "KC_GetFunctionList");
    if (!gl) {
        const char *e = dlerror();
        if (errbuf && errlen) { int n = snprintf(errbuf, *errlen, "dlsym KC_GetFunctionList: %s", e ? e : "?"); *errlen = n; }
        return 2;
    }
    int rv = gl(&kc);
    if (rv != 0 || !kc) {
        if (errbuf && errlen) { int n = snprintf(errbuf, *errlen, "KC_GetFunctionList rv=%d", rv); *errlen = n; }
        return 3;
    }
    return 0;
}

unsigned long probe_init(void) { return kc->KC_Init(); }

unsigned long probe_loadkey(int storage, const char *pass, int passlen,
                            const char *container, int clen,
                            char *aliasOut, int aliasCap) {
    if (aliasOut && aliasCap > 0) aliasOut[0] = 0;
    return kc->KC_LoadKeyStore(storage, (char *)pass, passlen,
                               (char *)container, clen, aliasOut);
}

unsigned long probe_export_cert(const char *alias, int flag, char *out, int *outlen) {
    return kc->X509ExportCertificateFromStore((char *)alias, flag, out, outlen);
}

unsigned long probe_cert_info(char *cert, int certlen, int propId,
                              unsigned char *out, int *outlen) {
    return kc->X509CertificateGetInfo(cert, certlen, propId, out, outlen);
}

unsigned long probe_sign_data(const char *alias, int flags, char *in, int inlen,
                              unsigned char *out, int *outlen) {
    return kc->SignData((char *)alias, flags, in, inlen, NULL, 0, out, outlen);
}

unsigned long probe_verify_data(const char *alias, int flags, char *in, int inlen,
                                unsigned char *sign, int signlen,
                                char *outData, int *outDataLen,
                                char *outVerify, int *outVerifyLen,
                                int inCertId, char *outCert, int *outCertLen) {
    return kc->VerifyData((char *)alias, flags, in, inlen, sign, signlen,
                          outData, outDataLen, outVerify, outVerifyLen,
                          inCertId, outCert, outCertLen);
}

unsigned long probe_time_from_sig(char *in, int inlen, int flags, int sigid,
                                  long long *outTime) {
    time_t t = 0;
    unsigned long rv = kc->KC_GetTimeFromSig(in, inlen, flags, sigid, &t);
    if (outTime) *outTime = (long long)t;
    return rv;
}

unsigned long probe_lasterr(char *out, int *outlen) {
    return kc->KC_GetLastErrorString(out, outlen);
}

void probe_finalize(void) {
    if (kc) { kc->KC_XMLFinalize(); kc->KC_Finalize(); }
}

unsigned long probe_load_cert_file(const char *path, int certType) {
    return kc->X509LoadCertificateFromFile((char *)path, certType);
}

unsigned long probe_validate(char *cert, int certlen, int validType,
                             const char *validPath, long long checkTime,
                             char *outInfo, int *outInfoLen, int flag,
                             char *getOcsp, int *getOcspLen) {
    return kc->X509ValidateCertificate(cert, certlen, validType, (char *)validPath,
                                       checkTime, outInfo, outInfoLen, flag,
                                       getOcsp, getOcspLen);
}

unsigned long probe_cert_from_cms(char *cms, int cmslen, int sigId, int flags,
                                  char *out, int *outLen) {
    return kc->KC_GetCertFromCMS(cms, cmslen, sigId, flags, out, outLen);
}

unsigned long probe_sign_data_co(const char *alias, int flags, char *in, int inlen,
                                 unsigned char *inSign, int inSignLen,
                                 unsigned char *out, int *outlen) {
    return kc->SignData((char *)alias, flags, in, inlen, inSign, inSignLen, out, outlen);
}

unsigned long probe_sign_xml(const char *alias, int flags, char *inXml, int inLen,
                             unsigned char *out, int *outLen,
                             const char *nodeId, const char *parentNode,
                             const char *parentNs) {
    return kc->SignXML((char *)alias, flags, inXml, inLen, out, outLen,
                       (char *)nodeId, (char *)parentNode, (char *)parentNs);
}

unsigned long probe_verify_xml(const char *alias, int flags, char *inXml,
                               int inLen, char *outInfo, int *outLen) {
    return kc->VerifyXML((char *)alias, flags, inXml, inLen, outInfo, outLen);
}

unsigned long probe_sigalg_from_xml(const char *xml, int len, char *out, int *outLen) {
    return kc->KC_getSigAlgFromXML(xml, len, out, outLen);
}

unsigned long probe_cert_from_xml(const char *xml, int len, int sigId,
                                  char *out, int *outLen) {
    return kc->KC_getCertFromXML(xml, len, sigId, out, outLen);
}
