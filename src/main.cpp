/*
 * OpenRAR - Clean-Room RAR 5.0 Compressor & Archiver CLI Entrypoint
 * Replicates the official WinRAR CLI (Rar.exe) and unrar-free CLI interface
 * for educational and research purposes, without any proprietary RARLAB code
 * or commercial registration/activation mechanism.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_cli.h"
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

static std::string wide_to_utf8_arg(const wchar_t* ws) {
    if (!ws || !*ws) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return std::string();
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &s[0], len - 1, nullptr, nullptr);
    return s;
}
#endif

int main(int argc, char* argv[]) {
    std::vector<std::string> utf8_args;
#ifdef _WIN32
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv && wargc > 0) {
        wchar_t mod_path[MAX_PATH * 4] = {0};
        DWORD mod_len = GetModuleFileNameW(nullptr, mod_path, (DWORD)(sizeof(mod_path) / sizeof(wchar_t)));
        if (mod_len > 0) {
            utf8_args.push_back(wide_to_utf8_arg(mod_path));
        } else {
            utf8_args.push_back(wide_to_utf8_arg(wargv[0]));
        }
        for (int i = 1; i < wargc; ++i) {
            utf8_args.push_back(wide_to_utf8_arg(wargv[i]));
        }
        LocalFree(wargv);
    } else
#endif
    {
        for (int i = 0; i < argc; ++i) {
            utf8_args.emplace_back(argv[i] ? argv[i] : "");
        }
    }

    return openrar::CliRunner::run((int)utf8_args.size(), utf8_args);
}
