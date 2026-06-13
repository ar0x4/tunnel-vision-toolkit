/*
 * gsa_enum.c — GSA Reconnaissance BOF
 * Enumerates Microsoft Global Secure Access (ZTNA v2) installation,
 * services, processes, registry config, security posture, and
 * forwarding profile with full JSON dump.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "badger_exports.h"

DECLSPEC_IMPORT DWORD  Kernel32$GetLastError();
DECLSPEC_IMPORT BOOL   Kernel32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE Kernel32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   Kernel32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   Kernel32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT DWORD  Kernel32$GetFileAttributesA(LPCSTR);

DECLSPEC_IMPORT LONG    Advapi32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    Advapi32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS Advapi32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS Advapi32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS Advapi32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

DECLSPEC_IMPORT DWORD Version$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT BOOL  Version$VerQueryValueA(LPCVOID, LPCSTR, LPVOID *, PUINT);
DECLSPEC_IMPORT BOOL  Version$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);

DECLSPEC_IMPORT int    Msvcrt$sprintf(char *, const char *, ...);
DECLSPEC_IMPORT char  *Msvcrt$strstr(const char *, const char *);
DECLSPEC_IMPORT int    Msvcrt$_strnicmp(const char *, const char *, size_t);
DECLSPEC_IMPORT int    Msvcrt$_stricmp(const char *, const char *);
DECLSPEC_IMPORT size_t Msvcrt$strlen(const char *);

DECLSPEC_IMPORT SC_HANDLE Advapi32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE Advapi32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL      Advapi32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL      Advapi32$CloseServiceHandle(SC_HANDLE);

static const char *GSA_INSTALL_DIR = "C:\\Program Files\\Global Secure Access Client";
static const char *GSA_KEY         = "SOFTWARE\\Microsoft\\Global Secure Access Client";
static const char *GSA_KEY_HKCU    = "Software\\Microsoft\\Global Secure Access Client";

static const char *ServiceStateStr(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:       return "STOPPED";
        case SERVICE_START_PENDING: return "START_PENDING";
        case SERVICE_STOP_PENDING:  return "STOP_PENDING";
        case SERVICE_RUNNING:       return "RUNNING";
        case SERVICE_PAUSED:        return "PAUSED";
        default:                    return "UNKNOWN";
    }
}

static void PrintError(WCHAR **dispatch, const char *ctx) {
    DWORD err = Kernel32$GetLastError();
    if (err == 5)
        BadgerDispatch(dispatch, "[-] %s: access denied\n", ctx);
    else
        BadgerDispatch(dispatch, "[-] %s: error %lu\n", ctx, err);
}

static BOOL ReadRegDword(HKEY root, const char *subkey, const char *name, DWORD *out) {
    HKEY hk;
    if (Advapi32$RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD type = 0, size = sizeof(DWORD);
    LSTATUS s = Advapi32$RegQueryValueExA(hk, name, NULL, &type, (LPBYTE)out, &size);
    Advapi32$RegCloseKey(hk);
    return (s == ERROR_SUCCESS && type == REG_DWORD);
}

static BOOL ReadRegString(HKEY root, const char *subkey, const char *name, char *buf, DWORD bufSize) {
    HKEY hk;
    if (Advapi32$RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD type = 0, size = bufSize;
    BadgerMemset(buf, 0, bufSize);
    LSTATUS s = Advapi32$RegQueryValueExA(hk, name, NULL, &type, (LPBYTE)buf, &size);
    Advapi32$RegCloseKey(hk);
    return (s == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ));
}

static int CountSubstring(const char *haystack, const char *needle) {
    int count = 0;
    const char *p = haystack;
    size_t nlen = Msvcrt$strlen(needle);
    while ((p = Msvcrt$strstr(p, needle)) != NULL) {
        count++;
        p += nlen;
    }
    return count;
}

void EnumInstallation(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === Installation & Version ===\n");

    char path[MAX_PATH];
    const char *bins[] = {
        "GlobalSecureAccessClient.exe",
        "GlobalSecureAccessTunnelingService.exe",
        "GlobalSecureAccessEngineService.exe",
        "GlobalSecureAccessPolicyRetrieverService.exe",
        NULL
    };

    DWORD attrs = Kernel32$GetFileAttributesA(GSA_INSTALL_DIR);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        BadgerDispatch(dispatch, "[-] GSA not installed\n");
        return;
    }
    BadgerDispatch(dispatch, "[+] Install dir: %s\n", GSA_INSTALL_DIR);

    for (int i = 0; bins[i]; i++) {
        Msvcrt$sprintf(path, "%s\\%s", GSA_INSTALL_DIR, bins[i]);
        if (Kernel32$GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
            continue;

        DWORD handle = 0;
        DWORD size = Version$GetFileVersionInfoSizeA(path, &handle);
        if (size > 0) {
            PVOID vd = BadgerAlloc(size);
            if (vd && Version$GetFileVersionInfoA(path, handle, size, vd)) {
                VS_FIXEDFILEINFO *fi = NULL;
                UINT len = 0;
                if (Version$VerQueryValueA(vd, "\\", (LPVOID *)&fi, &len) && len > 0)
                    BadgerDispatch(dispatch, "[+] %-48s  v%lu.%lu.%lu.%lu\n", bins[i],
                        HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS),
                        HIWORD(fi->dwFileVersionLS), LOWORD(fi->dwFileVersionLS));
            }
            if (vd) BadgerFree(&vd);
        } else {
            BadgerDispatch(dispatch, "[+] %-48s  (no version info)\n", bins[i]);
        }
    }

    const char *subdirs[] = { "Cache Files", "Logs", "LogsCollector", "TrayApp", NULL };
    for (int i = 0; subdirs[i]; i++) {
        Msvcrt$sprintf(path, "%s\\%s", GSA_INSTALL_DIR, subdirs[i]);
        BadgerDispatch(dispatch, "    %-20s  %s\n", subdirs[i],
            (Kernel32$GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) ? "exists" : "missing");
    }
}

void EnumServices(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === GSA Windows Services ===\n");

    SC_HANDLE hSCM = Advapi32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintError(dispatch, "OpenSCManager"); return; }

    struct { const char *name; const char *label; } svcs[] = {
        { "GlobalSecureAccessTunnelingService",      "Tunneling Service" },
        { "GlobalSecureAccessEngineService",         "Engine Service" },
        { "GlobalSecureAccessPolicyRetrieverService", "Policy Retriever" },
        { "GlobalSecureAccessDriver",                "Kernel Driver" },
        { NULL, NULL }
    };

    int running = 0;
    for (int i = 0; svcs[i].name; i++) {
        SC_HANDLE hSvc = Advapi32$OpenServiceA(hSCM, svcs[i].name, SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS ss;
            BadgerMemset(&ss, 0, sizeof(ss));
            if (Advapi32$QueryServiceStatus(hSvc, &ss)) {
                const char *m = (ss.dwCurrentState == SERVICE_RUNNING) ? "+" : "-";
                BadgerDispatch(dispatch, "[%s] %-24s  %s\n", m, svcs[i].label, ServiceStateStr(ss.dwCurrentState));
                if (ss.dwCurrentState == SERVICE_RUNNING) running++;
            } else {
                PrintError(dispatch, svcs[i].label);
            }
            Advapi32$CloseServiceHandle(hSvc);
        } else {
            DWORD err = Kernel32$GetLastError();
            if (err == 5)
                BadgerDispatch(dispatch, "[-] %-24s  access denied\n", svcs[i].label);
            else if (err == 1060)
                BadgerDispatch(dispatch, "[-] %-24s  not installed\n", svcs[i].label);
            else
                BadgerDispatch(dispatch, "[-] %-24s  error %lu\n", svcs[i].label, err);
        }
    }

    Advapi32$CloseServiceHandle(hSCM);
    BadgerDispatch(dispatch, "[*] %d of 4 services running\n", running);
}

void EnumProcesses(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === GSA Processes ===\n");

    HANDLE hSnap = Kernel32$CreateToolhelp32Snapshot(0x00000002, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { PrintError(dispatch, "Snapshot"); return; }

    PROCESSENTRY32 pe;
    BadgerMemset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    static const char *names[] = {
        "GlobalSecureAccessClient.exe",
        "GlobalSecureAccessTunnelingService.exe",
        "GlobalSecureAccessEngineService.exe",
        "GlobalSecureAccessPolicyRetrieverService.exe",
        "GlobalSecureAccessClientManagerService.exe",
        "GlobalSecureAccessForwardingProfileService.exe",
        NULL
    };

    int found = 0;
    if (Kernel32$Process32First(hSnap, &pe)) {
        do {
            BOOL match = FALSE;
            for (int i = 0; names[i]; i++) {
                if (Msvcrt$_stricmp(pe.szExeFile, names[i]) == 0) { match = TRUE; break; }
            }
            if (!match)
                match = (Msvcrt$_strnicmp(pe.szExeFile, "GlobalSecureAccess", 18) == 0);

            if (match) {
                BadgerDispatch(dispatch, "[+] PID: %-6lu  PPID: %-6lu  Threads: %-3lu  %s\n",
                    pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads, pe.szExeFile);
                found++;
            }
        } while (Kernel32$Process32Next(hSnap, &pe));
    } else {
        PrintError(dispatch, "Process32First");
    }

    Kernel32$CloseHandle(hSnap);
    if (!found) BadgerDispatch(dispatch, "[-] No GSA processes found\n");
    else        BadgerDispatch(dispatch, "[*] Found %d GSA process(es)\n", found);
}

void EnumRegistry(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === GSA Registry ===\n");

    DWORD regBufSize = 1024;
    PVOID regBuf = BadgerAlloc(regBufSize);
    if (!regBuf) { BadgerDispatch(dispatch, "[-] alloc failed\n"); return; }

    char vname[128];
    DWORD nameLen, dataLen, type;
    HKEY hKey;

    BadgerDispatch(dispatch, "\n    [HKLM\\%s]\n", GSA_KEY);
    LONG status = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, GSA_KEY, 0, KEY_READ, &hKey);
    if (status == 5)
        BadgerDispatch(dispatch, "    [-] access denied\n");
    else if (status != ERROR_SUCCESS)
        BadgerDispatch(dispatch, "    [-] not found (error %ld)\n", status);
    else {
        DWORD idx = 0;
        while (1) {
            nameLen = sizeof(vname);
            dataLen = regBufSize;
            BadgerMemset(vname, 0, sizeof(vname));
            BadgerMemset(regBuf, 0, regBufSize);

            if (Advapi32$RegEnumValueA(hKey, idx, vname, &nameLen, NULL, &type, (LPBYTE)regBuf, &dataLen) != ERROR_SUCCESS)
                break;

            if (Msvcrt$_stricmp(vname, "ForwardingProfile") == 0)
                BadgerDispatch(dispatch, "    [+] %-40s = <JSON, %lu bytes>\n", vname, dataLen);
            else if ((type == REG_SZ || type == REG_EXPAND_SZ) && dataLen <= 200)
                BadgerDispatch(dispatch, "    [+] %-40s = %s\n", vname, (char *)regBuf);
            else if ((type == REG_SZ || type == REG_EXPAND_SZ) && dataLen > 200)
                BadgerDispatch(dispatch, "    [+] %-40s = <string, %lu bytes>\n", vname, dataLen);
            else if (type == REG_DWORD && dataLen >= 4)
                BadgerDispatch(dispatch, "    [+] %-40s = 0x%08x (%lu)\n", vname, *(DWORD *)regBuf, *(DWORD *)regBuf);
            else if (type == REG_BINARY)
                BadgerDispatch(dispatch, "    [+] %-40s = <binary, %lu bytes>\n", vname, dataLen);
            else if (type == REG_QWORD && dataLen >= 8)
                BadgerDispatch(dispatch, "    [+] %-40s = 0x%llx\n", vname, *(unsigned long long *)regBuf);
            idx++;
        }
        if (!idx) BadgerDispatch(dispatch, "    [-] empty\n");

        idx = 0;
        while (1) {
            nameLen = sizeof(vname);
            BadgerMemset(vname, 0, sizeof(vname));
            if (Advapi32$RegEnumKeyExA(hKey, idx, vname, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            BadgerDispatch(dispatch, "    [+] Subkey: %s\n", vname);
            idx++;
        }
        Advapi32$RegCloseKey(hKey);
    }

    BadgerDispatch(dispatch, "\n    [HKCU\\%s]\n", GSA_KEY_HKCU);
    status = Advapi32$RegOpenKeyExA(HKEY_CURRENT_USER, GSA_KEY_HKCU, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        BadgerDispatch(dispatch, "    [-] not found\n");
    } else {
        DWORD idx = 0;
        while (1) {
            nameLen = sizeof(vname);
            dataLen = regBufSize;
            BadgerMemset(vname, 0, sizeof(vname));
            BadgerMemset(regBuf, 0, regBufSize);
            if (Advapi32$RegEnumValueA(hKey, idx, vname, &nameLen, NULL, &type, (LPBYTE)regBuf, &dataLen) != ERROR_SUCCESS)
                break;
            if (type == REG_SZ || type == REG_EXPAND_SZ)
                BadgerDispatch(dispatch, "    [+] %-40s = %s\n", vname, (char *)regBuf);
            else if (type == REG_DWORD && dataLen >= 4)
                BadgerDispatch(dispatch, "    [+] %-40s = 0x%08x (%lu)\n", vname, *(DWORD *)regBuf, *(DWORD *)regBuf);
            idx++;
        }
        if (!idx) BadgerDispatch(dispatch, "    [-] empty\n");
        Advapi32$RegCloseKey(hKey);
    }

    BadgerFree(&regBuf);

    DWORD ipv6 = 0;
    if (ReadRegDword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", "DisabledComponents", &ipv6))
        BadgerDispatch(dispatch, "\n    [IPv6] DisabledComponents = 0x%02x %s\n", ipv6,
            (ipv6 == 0x20) ? "(IPv4 preferred)" : (ipv6 == 0xFF) ? "(IPv6 disabled)" : "");
    else
        BadgerDispatch(dispatch, "\n    [IPv6] DisabledComponents not set (IPv6 active)\n");
}

void EnumSecurityPosture(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === Security Posture ===\n");

    DWORD val;

    if (ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "RestrictNonPrivilegedUsers", &val))
        BadgerDispatch(dispatch, "[%s] RestrictNonPrivilegedUsers = %lu  -> %s\n",
            val ? "*" : "!", val, val ? "UAC required to disable" : "any user can disable");
    else
        BadgerDispatch(dispatch, "[!] RestrictNonPrivilegedUsers not set -> any user can disable (default)\n");

    if (ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "HideDisableButton", &val))
        BadgerDispatch(dispatch, "[%s] HideDisableButton = %lu          -> %s\n",
            val ? "*" : "!", val, val ? "hidden" : "visible in tray");
    else
        BadgerDispatch(dispatch, "[!] HideDisableButton not set       -> visible (default)\n");

    if (ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "HideSignOutButton", &val))
        BadgerDispatch(dispatch, "[*] HideSignOutButton = %lu          -> %s\n",
            val, val ? "hidden" : "visible (re-auth possible)");
    else
        BadgerDispatch(dispatch, "[*] HideSignOutButton not set       -> hidden (default)\n");

    if (ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "HideDisablePrivateAccessButton", &val))
        BadgerDispatch(dispatch, "[*] HideDisablePrivateAccessButton = %lu -> %s\n",
            val, val ? "hidden" : "visible (can bypass PA)");
    else
        BadgerDispatch(dispatch, "[*] HideDisablePrivateAccessButton not set -> hidden (default)\n");

    if (ReadRegDword(HKEY_CURRENT_USER, GSA_KEY_HKCU, "IsPrivateAccessDisabledByUser", &val))
        BadgerDispatch(dispatch, "[%s] IsPrivateAccessDisabledByUser = %lu -> %s\n",
            (val == 1) ? "!" : "*", val, (val == 1) ? "Private Access BYPASSED" : "active");
    else
        BadgerDispatch(dispatch, "[*] IsPrivateAccessDisabledByUser not set -> active (default)\n");

    char certCN[128];
    if (ReadRegString(HKEY_LOCAL_MACHINE, GSA_KEY, "CertCommonName", certCN, sizeof(certCN)))
        BadgerDispatch(dispatch, "[+] mTLS CertCommonName = %s\n", certCN);
    else
        BadgerDispatch(dispatch, "[*] mTLS CertCommonName not set\n");

    DWORD r = 0, h = 0;
    BOOL hasR = ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "RestrictNonPrivilegedUsers", &r);
    BOOL hasH = ReadRegDword(HKEY_LOCAL_MACHINE, GSA_KEY, "HideDisableButton", &h);

    BadgerDispatch(dispatch, "\n    --- Summary ---\n");
    if ((!hasR || !r) && (!hasH || !h))
        BadgerDispatch(dispatch, "    [!] Any user can disable GSA from visible tray button\n");
    else if (!hasR || !r)
        BadgerDispatch(dispatch, "    [!] Any user can disable GSA (button hidden but API accessible)\n");
    else
        BadgerDispatch(dispatch, "    [*] UAC required to disable (hardened)\n");
}

void EnumForwardingProfile(WCHAR **dispatch) {
    BadgerDispatch(dispatch, "\n[*] === Forwarding Profile ===\n");

    char ts[128];
    if (ReadRegString(HKEY_LOCAL_MACHINE, GSA_KEY, "ForwardingProfileTimestamp", ts, sizeof(ts)))
        BadgerDispatch(dispatch, "[+] Last checked: %s\n", ts);

    HKEY hKey;
    LONG s = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, GSA_KEY, 0, KEY_READ, &hKey);
    if (s == 5)    { BadgerDispatch(dispatch, "[-] access denied\n"); return; }
    if (s != ERROR_SUCCESS) { BadgerDispatch(dispatch, "[-] key not found\n"); return; }

    DWORD type = 0, dataSize = 0;
    Advapi32$RegQueryValueExA(hKey, "ForwardingProfile", NULL, &type, NULL, &dataSize);
    if (!dataSize || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        BadgerDispatch(dispatch, "[-] ForwardingProfile not found\n");
        Advapi32$RegCloseKey(hKey);
        return;
    }

    BadgerDispatch(dispatch, "[+] Size: %lu bytes\n", dataSize);

    PVOID buf = BadgerAlloc(dataSize + 1);
    if (!buf) { BadgerDispatch(dispatch, "[-] alloc failed\n"); Advapi32$RegCloseKey(hKey); return; }

    BadgerMemset(buf, 0, dataSize + 1);
    if (Advapi32$RegQueryValueExA(hKey, "ForwardingProfile", NULL, &type, (LPBYTE)buf, &dataSize) != ERROR_SUCCESS) {
        BadgerDispatch(dispatch, "[-] read failed\n");
        BadgerFree(&buf);
        Advapi32$RegCloseKey(hKey);
        return;
    }
    Advapi32$RegCloseKey(hKey);

    char *json = (char *)buf;

    char *p = Msvcrt$strstr(json, "\"tenantId\"");
    if (!p) p = Msvcrt$strstr(json, "\"TenantId\"");
    if (p) {
        char *q = Msvcrt$strstr(p, ":\"");
        if (!q) q = Msvcrt$strstr(p, ": \"");
        if (q) {
            q = Msvcrt$strstr(q, "\"") + 1;
            char tid[64];
            BadgerMemset(tid, 0, sizeof(tid));
            int n = 0;
            while (*q && *q != '"' && n < 60) tid[n++] = *q++;
            BadgerDispatch(dispatch, "[+] Tenant ID: %s\n", tid);
        }
    }

    BOOL hasM365    = (Msvcrt$strstr(json, "m365") || Msvcrt$strstr(json, "M365") || Msvcrt$strstr(json, "microsoft365"));
    BOOL hasPrivate = (Msvcrt$strstr(json, "privateAccess") || Msvcrt$strstr(json, "PrivateAccess") || Msvcrt$strstr(json, "private"));
    BOOL hasInternet = (Msvcrt$strstr(json, "internetAccess") || Msvcrt$strstr(json, "InternetAccess") || Msvcrt$strstr(json, "internet"));

    BadgerDispatch(dispatch, "[+] Channels: M365=%s  Private=%s  Internet=%s\n",
        hasM365 ? "yes" : "no", hasPrivate ? "yes" : "no", hasInternet ? "yes" : "no");

    int rules = CountSubstring(json, "\"ruleId\"");
    if (!rules) rules = CountSubstring(json, "\"RuleId\"");
    int fqdns = CountSubstring(json, "\"fqdn\"");
    if (!fqdns) fqdns = CountSubstring(json, "\"Fqdn\"");
    int ips = CountSubstring(json, "\"ip\"");
    BadgerDispatch(dispatch, "[+] Rules: ~%d  FQDN: ~%d  IP: ~%d\n", rules, fqdns, ips);

    p = Msvcrt$strstr(json, "globalsecureaccess.microsoft.com");
    if (p) {
        char *start = p;
        while (start > json && *(start - 1) != '"' && *(start - 1) != ' ') start--;
        char edge[256];
        BadgerMemset(edge, 0, sizeof(edge));
        int n = 0;
        while (*start && *start != '"' && *start != ',' && *start != '}' && n < 250)
            edge[n++] = *start++;
        BadgerDispatch(dispatch, "[+] Edge: %s\n", edge);
    }

    if (Msvcrt$strstr(json, "\"block\"") || Msvcrt$strstr(json, "\"Block\""))
        BadgerDispatch(dispatch, "[+] Hardening: BLOCK\n");
    else if (Msvcrt$strstr(json, "\"bypass\"") || Msvcrt$strstr(json, "\"Bypass\""))
        BadgerDispatch(dispatch, "[+] Hardening: BYPASS\n");

    BadgerDispatch(dispatch, "\n[*] === Full Forwarding Profile (%lu bytes) ===\n", dataSize);

    size_t total = Msvcrt$strlen(json);
    size_t off = 0;
    while (off < total) {
        size_t chunk = total - off;
        if (chunk > 1800) chunk = 1800;
        char saved = json[off + chunk];
        json[off + chunk] = '\0';
        BadgerDispatch(dispatch, "%s", json + off);
        json[off + chunk] = saved;
        off += chunk;
    }
    BadgerDispatch(dispatch, "\n");

    BadgerFree(&buf);
}

void coffee(char **argv, int argc, WCHAR **dispatch) {
    g_dispatch = dispatch;

    BadgerDispatch(dispatch, "============================================\n");
    BadgerDispatch(dispatch, "  GSA Recon — Global Secure Access Enum\n");
    BadgerDispatch(dispatch, "============================================\n");

    EnumInstallation(dispatch);
    EnumServices(dispatch);
    EnumProcesses(dispatch);
    EnumRegistry(dispatch);
    EnumSecurityPosture(dispatch);
    EnumForwardingProfile(dispatch);

    BadgerDispatch(dispatch, "\n[*] Done\n");
}
