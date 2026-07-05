#ifndef QOLTANBA_SHIM_H
#define QOLTANBA_SHIM_H

/* Thin C wrappers over the KalkanCrypt function table (stKCFunctionsType)
 * obtained via KC_GetFunctionList. cgo calls library methods through these
 * wrappers instead of touching the pointers inside the struct.
 *
 * The instance is not global: each KcInstance holds its own handle and function
 * table, so the pool can bring up several independent library instances, each
 * owned by one worker (thread safety through isolation, not a global mutex). */

typedef struct KcInstance KcInstance;

/* kc_open loads the library and extracts its function table into a new instance.
 *
 *   wrapperPath    path to libkalkancryptwr-64.so. In isolated mode this MUST be
 *                  a wrapper whose dependencies (iconv shim, libkalkancrypto,
 *                  libm, libpcsclite) are baked into DT_NEEDED (patchelf
 *                  --add-needed, done on the Go side): dlmopen rejects
 *                  RTLD_GLOBAL, so external symbols enter the namespace only via
 *                  the wrapper's own NEEDED. Then a fresh namespace is
 *                  self-contained and carries its own copy of libkalkancrypto —
 *                  real isolation of crypto-engine state.
 *   isolated       1: a private link namespace (dlmopen LM_ID_NEWLM, Linux);
 *                  0: shared dlopen (symbols from the base namespace LD_PRELOAD).
 *   sharedFallback set to 1 if isolated was requested but dlmopen failed and we
 *                  fell back to a shared dlopen (isolation NOT achieved).
 *
 * Returns a KcInstance* or NULL on error (text in errbuf). */
KcInstance *kc_open(const char *wrapperPath, int isolated,
                    int *sharedFallback, char *errbuf, int *errlen);

unsigned long kc_init(KcInstance *in);
/* kc_close releases an instance. isolated!=0 tears the instance down fully
 * (KC_XMLFinalize + KC_Finalize + dlclose) — safe for a private dlmopen
 * namespace. isolated==0 keeps the process-global shared library mapped and only
 * frees the wrapper struct: finalizing/unloading it would corrupt libxml2/OpenSSL
 * state a later kc_open in the same process reuses (see kc_close in shim.c). */
void kc_close(KcInstance *in, int isolated);

/* kc_has reports whether a method is available (table pointer != NULL). id is
 * one of the KC_CAP_* values below; used to build the capability map. */
int kc_has(KcInstance *in, int id);

unsigned long kc_loadkey(KcInstance *in, int storage, const char *pass, int passlen,
                         const char *container, int clen, char *aliasOut, int aliasCap);
unsigned long kc_export_cert(KcInstance *in, const char *alias, int flag,
                             char *out, int *outlen);
unsigned long kc_cert_info(KcInstance *in, char *cert, int certlen, int propId,
                           unsigned char *out, int *outlen);
unsigned long kc_sign_data(KcInstance *in, const char *alias, int flags,
                           char *data, int datalen,
                           unsigned char *inSign, int inSignLen,
                           unsigned char *out, int *outlen);
unsigned long kc_verify_data(KcInstance *in, const char *alias, int flags,
                             char *data, int datalen,
                             unsigned char *sign, int signlen,
                             char *outData, int *outDataLen,
                             char *outVerify, int *outVerifyLen,
                             int inCertId, char *outCert, int *outCertLen);
unsigned long kc_sign_xml(KcInstance *in, const char *alias, int flags,
                          char *inXml, int inLen, unsigned char *out, int *outLen,
                          const char *nodeId, const char *parentNode,
                          const char *parentNs);
unsigned long kc_sign_wsse(KcInstance *in, const char *alias, unsigned long flags,
                           char *inXml, int inLen, unsigned char *out, int *outLen,
                           const char *nodeId);
unsigned long kc_hash_data(KcInstance *in, const char *algorithm, int flags,
                           char *data, int len, unsigned char *out, int *outLen);
unsigned long kc_sign_hash(KcInstance *in, const char *alias, int flags,
                           char *hash, int hashLen, unsigned char *out, int *outLen);
unsigned long kc_verify_xml(KcInstance *in, const char *alias, int flags,
                            char *inXml, int inLen, char *outInfo, int *outLen);
unsigned long kc_cert_from_cms(KcInstance *in, char *cms, int cmslen, int sigId,
                               int flags, char *out, int *outLen);
unsigned long kc_cert_from_xml(KcInstance *in, char *xml, int len, int sigId,
                               char *out, int *outLen);
unsigned long kc_sigalg_from_xml(KcInstance *in, char *xml, int len,
                                 char *out, int *outLen);
unsigned long kc_time_from_sig(KcInstance *in, char *in_, int inlen, int flags,
                               int sigid, long long *outTime);
unsigned long kc_load_cert_file(KcInstance *in, const char *path, int certType);
unsigned long kc_validate(KcInstance *in, char *cert, int certlen, int validType,
                          const char *validPath, long long checkTime,
                          char *outInfo, int *outInfoLen, int flag,
                          char *getOcsp, int *getOcspLen);
void kc_tsa_seturl(KcInstance *in, const char *url);
/* kc_set_proxy configures the library's internal HTTP proxy (OCSP/AIA/TSA/CA
 * download). Returns 0xFFFFFFFF if the loaded library lacks KC_SetProxy. */
unsigned long kc_set_proxy(KcInstance *in, int flags, const char *addr,
                           const char *port, const char *user, const char *pass);
unsigned long kc_lasterr(KcInstance *in, char *out, int *outlen);

/* Identifiers for kc_has. */
#define KC_CAP_SIGNDATA 1
#define KC_CAP_VERIFYDATA 2
#define KC_CAP_SIGNXML 3
#define KC_CAP_VERIFYXML 4
#define KC_CAP_CERTINFO 5
#define KC_CAP_VALIDATE 6
#define KC_CAP_TSA 7
#define KC_CAP_ZIPSIGN 8
#define KC_CAP_WSSE 9
#define KC_CAP_HASHDATA 10
#define KC_CAP_SIGNHASH 11
#define KC_CAP_EXPORTCERT 12

#endif
