/* Шим совместимости: libkalkancryptwr собрана против GNU libiconv (символы
 * libiconv/libiconv_open/libiconv_close), а в glibc эти функции называются
 * iconv/iconv_open/iconv_close. Предоставляем GNU-имена как тонкие обёртки над
 * glibc-версиями и подгружаем через LD_PRELOAD.
 *
 * Это артефакт окружения ПРОБНИКА (glibc-контейнер). В проде совместимость с
 * iconv — часть требований к среде потребителя (см. §8 DESIGN.md). */
#include <iconv.h>
#include <stddef.h>

iconv_t libiconv_open(const char *tocode, const char *fromcode) {
    return iconv_open(tocode, fromcode);
}

size_t libiconv(iconv_t cd, char **inbuf, size_t *inbytesleft,
                char **outbuf, size_t *outbytesleft) {
    return iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}

int libiconv_close(iconv_t cd) {
    return iconv_close(cd);
}
