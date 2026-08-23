#ifndef PROBE_SHIM_H
#define PROBE_SHIM_H

/* Тонкие C-обёртки над таблицей функций KalkanCrypt (stKCFunctionsType),
 * получаемой через KC_GetFunctionList. Нужны, чтобы Go (cgo) вызывал методы
 * библиотеки, не работая напрямую с указателями на функции внутри структуры. */

unsigned long probe_load(const char *libpath, char *errbuf, int *errlen);
unsigned long probe_init(void);
unsigned long probe_loadkey(int storage, const char *pass, int passlen,
                            const char *container, int clen,
                            char *aliasOut, int aliasCap);
unsigned long probe_export_cert(const char *alias, int flag, char *out, int *outlen);
unsigned long probe_cert_info(char *cert, int certlen, int propId,
                              unsigned char *out, int *outlen);
unsigned long probe_sign_data(const char *alias, int flags, char *in, int inlen,
                              unsigned char *out, int *outlen);
unsigned long probe_verify_data(const char *alias, int flags, char *in, int inlen,
                                unsigned char *sign, int signlen,
                                char *outData, int *outDataLen,
                                char *outVerify, int *outVerifyLen,
                                int inCertId, char *outCert, int *outCertLen);
unsigned long probe_time_from_sig(char *in, int inlen, int flags, int sigid,
                                  long long *outTime);
unsigned long probe_lasterr(char *out, int *outlen);
void probe_finalize(void);

/* --- Расширение: цепочка, валидация, извлечение из CMS/XML --- */
unsigned long probe_load_cert_file(const char *path, int certType);
unsigned long probe_validate(char *cert, int certlen, int validType,
                             const char *validPath, long long checkTime,
                             char *outInfo, int *outInfoLen, int flag,
                             char *getOcsp, int *getOcspLen);
unsigned long probe_cert_from_cms(char *cms, int cmslen, int sigId, int flags,
                                  char *out, int *outLen);
/* Ко-подпись: добавить подпись к существующему CMS (передаётся в inSign). */
unsigned long probe_sign_data_co(const char *alias, int flags, char *in, int inlen,
                                 unsigned char *inSign, int inSignLen,
                                 unsigned char *out, int *outlen);
unsigned long probe_sign_xml(const char *alias, int flags, char *inXml, int inLen,
                             unsigned char *out, int *outLen,
                             const char *nodeId, const char *parentNode,
                             const char *parentNs);
unsigned long probe_verify_xml(const char *alias, int flags, char *inXml,
                               int inLen, char *outInfo, int *outLen);
unsigned long probe_sigalg_from_xml(const char *xml, int len, char *out, int *outLen);
unsigned long probe_cert_from_xml(const char *xml, int len, int sigId,
                                  char *out, int *outLen);

#endif
