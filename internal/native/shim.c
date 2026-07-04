/* Implementation of the C wrappers over the KalkanCrypt function table.
 *
 * Instance isolation (isolated mode) realizes the "each worker its own Kalkan"
 * requirement. On Linux we use dlmopen(LM_ID_NEWLM): a fresh link namespace is
 * an independent copy of the wrapper's global state, and because the wrapper's
 * dependencies are baked into its DT_NEEDED (see kc_open / the Go side), the
 * namespace also pulls its own libkalkancrypto — isolating crypto-engine state.
 * If the namespace does not assemble on the real library we fall back to a
 * shared dlopen and signal sharedFallback=1. */

#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Platform loader seam. POSIX uses dlopen/dlsym; Windows uses LoadLibrary.
 * Isolated mode (dlmopen) stays Linux-only below; these portable helpers cover
 * the shared-load path used everywhere else. */
#ifdef _WIN32
#include <windows.h>
static void *kc_load(const char *path) {
    /* Altered search path so the wrapper's sibling DLLs (libcrypto/libssl)
     * resolve from its own directory; path should be absolute. */
    return (void *)LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}
static void *kc_sym(void *h, const char *name) {
    return (void *)(void (*)(void))GetProcAddress((HMODULE)h, name);
}
static void kc_unload(void *h) { FreeLibrary((HMODULE)h); }
static void kc_loaderr(char *buf, int cap) {
    if (buf && cap > 0) snprintf(buf, cap, "error %lu", (unsigned long)GetLastError());
}
#else
#include <dlfcn.h>
static void *kc_load(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }
static void *kc_sym(void *h, const char *name) { return dlsym(h, name); }
static void kc_unload(void *h) { dlclose(h); }
static void kc_loaderr(char *buf, int cap) {
    const char *e = dlerror();
    if (buf && cap > 0) snprintf(buf, cap, "%s", e ? e : "?");
}
#endif

#include "KalkanCrypt.h"
#include "shim.h"

struct KcInstance {
    void *handle;
    stKCFunctionsType *kc;
};

/* resolve_table extracts the function table from an already-loaded handle. */
static unsigned long resolve_table(void *h, stKCFunctionsType **out,
                                   char *errbuf, int *errlen) {
    typedef int (*getlist_t)(stKCFunctionsType **);
    getlist_t gl = (getlist_t)kc_sym(h, "KC_GetFunctionList");
    if (!gl) {
        if (errbuf && errlen) {
            char e[256];
            kc_loaderr(e, sizeof e);
            *errlen = snprintf(errbuf, *errlen, "resolve KC_GetFunctionList: %s", e);
        }
        return 2;
    }
    stKCFunctionsType *kc = NULL;
    int rv = gl(&kc);
    if (rv != 0 || !kc) {
        if (errbuf && errlen)
            *errlen = snprintf(errbuf, *errlen, "KC_GetFunctionList rv=%d", rv);
        return 3;
    }
    *out = kc;
    return 0;
}

KcInstance *kc_open(const char *wrapperPath, int isolated,
                    int *sharedFallback, char *errbuf, int *errlen) {
    void *handle = NULL;
    if (sharedFallback) *sharedFallback = 0;

#ifdef __linux__
    if (isolated) {
        /* Fresh link namespace: the wrapper (with deps in DT_NEEDED) pulls its
         * own copy of libkalkancrypto, isolating crypto-engine state.
         * RTLD_GLOBAL is not allowed here (dlmopen rejects it). */
        handle = dlmopen(LM_ID_NEWLM, wrapperPath, RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "[kc_open] dlmopen(LM_ID_NEWLM, %s): %s\n", wrapperPath, dlerror());
            if (sharedFallback) *sharedFallback = 1; /* isolation failed */
        }
    }
#else
    if (isolated && sharedFallback) *sharedFallback = 1; /* dlmopen is Linux-only */
#endif

    if (!handle) {
        handle = kc_load(wrapperPath);
        if (!handle) {
            if (errbuf && errlen) {
                char e[256];
                kc_loaderr(e, sizeof e);
                *errlen = snprintf(errbuf, *errlen, "load %s: %s", wrapperPath, e);
            }
            return NULL;
        }
    }

    stKCFunctionsType *kc = NULL;
    if (resolve_table(handle, &kc, errbuf, errlen) != 0) {
        kc_unload(handle);
        return NULL;
    }

    KcInstance *in = (KcInstance *)calloc(1, sizeof(KcInstance));
    if (!in) {
        kc_unload(handle);
        if (errbuf && errlen) *errlen = snprintf(errbuf, *errlen, "calloc failed");
        return NULL;
    }
    in->handle = handle;
    in->kc = kc;
    return in;
}

unsigned long kc_init(KcInstance *in) { return in->kc->KC_Init(); }

void kc_close(KcInstance *in) {
    if (!in) return;
    if (in->kc) {
        if (in->kc->KC_XMLFinalize) in->kc->KC_XMLFinalize();
        if (in->kc->KC_Finalize) in->kc->KC_Finalize();
    }
    if (in->handle) kc_unload(in->handle);
    free(in);
}

int kc_has(KcInstance *in, int id) {
    stKCFunctionsType *kc = in->kc;
    switch (id) {
    case KC_CAP_SIGNDATA:   return kc->SignData != NULL;
    case KC_CAP_VERIFYDATA: return kc->VerifyData != NULL;
    case KC_CAP_SIGNXML:    return kc->SignXML != NULL;
    case KC_CAP_VERIFYXML:  return kc->VerifyXML != NULL;
    case KC_CAP_CERTINFO:   return kc->X509CertificateGetInfo != NULL;
    case KC_CAP_VALIDATE:   return kc->X509ValidateCertificate != NULL;
    case KC_CAP_TSA:        return kc->KC_TSASetUrl != NULL;
    case KC_CAP_ZIPSIGN:    return kc->ZipConSign != NULL;
    case KC_CAP_WSSE:       return kc->SignWSSE != NULL;
    case KC_CAP_HASHDATA:   return kc->HashData != NULL;
    case KC_CAP_SIGNHASH:   return kc->SignHash != NULL;
    case KC_CAP_EXPORTCERT: return kc->X509ExportCertificateFromStore != NULL;
    default:                return 0;
    }
}

unsigned long kc_loadkey(KcInstance *in, int storage, const char *pass, int passlen,
                         const char *container, int clen, char *aliasOut, int aliasCap) {
    if (aliasOut && aliasCap > 0) aliasOut[0] = 0;
    return in->kc->KC_LoadKeyStore(storage, (char *)pass, passlen,
                                   (char *)container, clen, aliasOut);
}

unsigned long kc_export_cert(KcInstance *in, const char *alias, int flag,
                             char *out, int *outlen) {
    return in->kc->X509ExportCertificateFromStore((char *)alias, flag, out, outlen);
}

unsigned long kc_cert_info(KcInstance *in, char *cert, int certlen, int propId,
                           unsigned char *out, int *outlen) {
    return in->kc->X509CertificateGetInfo(cert, certlen, propId, out, outlen);
}

unsigned long kc_sign_data(KcInstance *in, const char *alias, int flags,
                           char *data, int datalen,
                           unsigned char *inSign, int inSignLen,
                           unsigned char *out, int *outlen) {
    return in->kc->SignData((char *)alias, flags, data, datalen,
                            inSign, inSignLen, out, outlen);
}

unsigned long kc_verify_data(KcInstance *in, const char *alias, int flags,
                             char *data, int datalen,
                             unsigned char *sign, int signlen,
                             char *outData, int *outDataLen,
                             char *outVerify, int *outVerifyLen,
                             int inCertId, char *outCert, int *outCertLen) {
    return in->kc->VerifyData((char *)alias, flags, data, datalen, sign, signlen,
                              outData, outDataLen, outVerify, outVerifyLen,
                              inCertId, outCert, outCertLen);
}

unsigned long kc_sign_xml(KcInstance *in, const char *alias, int flags,
                          char *inXml, int inLen, unsigned char *out, int *outLen,
                          const char *nodeId, const char *parentNode,
                          const char *parentNs) {
    return in->kc->SignXML((char *)alias, flags, inXml, inLen, out, outLen,
                           (char *)nodeId, (char *)parentNode, (char *)parentNs);
}

unsigned long kc_verify_xml(KcInstance *in, const char *alias, int flags,
                            char *inXml, int inLen, char *outInfo, int *outLen) {
    return in->kc->VerifyXML((char *)alias, flags, inXml, inLen, outInfo, outLen);
}

unsigned long kc_sign_wsse(KcInstance *in, const char *alias, unsigned long flags,
                           char *inXml, int inLen, unsigned char *out, int *outLen,
                           const char *nodeId) {
    return in->kc->SignWSSE((char *)alias, flags, inXml, inLen, out, outLen,
                            (char *)nodeId);
}

unsigned long kc_hash_data(KcInstance *in, const char *algorithm, int flags,
                           char *data, int len, unsigned char *out, int *outLen) {
    return in->kc->HashData((char *)algorithm, flags, data, len, out, outLen);
}

unsigned long kc_sign_hash(KcInstance *in, const char *alias, int flags,
                           char *hash, int hashLen, unsigned char *out, int *outLen) {
    return in->kc->SignHash((char *)alias, flags, hash, hashLen, out, outLen);
}

unsigned long kc_cert_from_cms(KcInstance *in, char *cms, int cmslen, int sigId,
                               int flags, char *out, int *outLen) {
    return in->kc->KC_GetCertFromCMS(cms, cmslen, sigId, flags, out, outLen);
}

unsigned long kc_cert_from_xml(KcInstance *in, char *xml, int len, int sigId,
                               char *out, int *outLen) {
    return in->kc->KC_getCertFromXML(xml, len, sigId, out, outLen);
}

unsigned long kc_sigalg_from_xml(KcInstance *in, char *xml, int len,
                                 char *out, int *outLen) {
    return in->kc->KC_getSigAlgFromXML(xml, len, out, outLen);
}

unsigned long kc_time_from_sig(KcInstance *in, char *in_, int inlen, int flags,
                               int sigid, long long *outTime) {
    time_t t = 0;
    unsigned long rv = in->kc->KC_GetTimeFromSig(in_, inlen, flags, sigid, &t);
    if (outTime) *outTime = (long long)t;
    return rv;
}

unsigned long kc_load_cert_file(KcInstance *in, const char *path, int certType) {
    return in->kc->X509LoadCertificateFromFile((char *)path, certType);
}

unsigned long kc_validate(KcInstance *in, char *cert, int certlen, int validType,
                          const char *validPath, long long checkTime,
                          char *outInfo, int *outInfoLen, int flag,
                          char *getOcsp, int *getOcspLen) {
    return in->kc->X509ValidateCertificate(cert, certlen, validType, (char *)validPath,
                                           checkTime, outInfo, outInfoLen, flag,
                                           getOcsp, getOcspLen);
}

void kc_tsa_seturl(KcInstance *in, const char *url) {
    if (in->kc->KC_TSASetUrl) in->kc->KC_TSASetUrl((char *)url);
}

unsigned long kc_set_proxy(KcInstance *in, int flags, const char *addr,
                           const char *port, const char *user, const char *pass) {
    if (!in->kc->KC_SetProxy) return 0xFFFFFFFF;
    return in->kc->KC_SetProxy(flags, (char *)addr, (char *)port,
                               (char *)user, (char *)pass);
}

unsigned long kc_lasterr(KcInstance *in, char *out, int *outlen) {
    return in->kc->KC_GetLastErrorString(out, outlen);
}
