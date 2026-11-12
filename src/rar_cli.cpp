/*
 * OpenRAR - Clean-Room RAR 5.0 Command-Line Interface (CLI) Implementation
 * Replicates the official WinRAR CLI (Rar.exe) and unrar-free CLI behavior
 * without any proprietary code or registration/activation mechanism.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_cli.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace fs = std::filesystem;

namespace openrar {

namespace {

// UTF-8 <-> UTF-16 helpers for Windows filesystem and console
#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

std::string wide_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

fs::path make_fspath(const std::string& utf8_path) {
    return fs::path(utf8_to_wide(utf8_path));
}

std::string fspath_to_utf8(const fs::path& p) {
    return wide_to_utf8(p.wstring());
}
#else
fs::path make_fspath(const std::string& utf8_path) {
    return fs::path(utf8_path);
}

std::string fspath_to_utf8(const fs::path& p) {
    return p.string();
}
#endif

// Console-aware text output (uses WriteConsoleW on Windows interactive consoles to prevent GBK/UTF-8 garbling)
void print_stream(FILE* stream, const std::string& text) {
    if (text.empty()) return;
#ifdef _WIN32
    int fd = _fileno(stream);
    if (fd >= 0) {
        HANDLE h = (HANDLE)_get_osfhandle(fd);
        DWORD mode = 0;
        if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
            std::wstring ws = utf8_to_wide(text);
            DWORD written = 0;
            WriteConsoleW(h, ws.data(), (DWORD)ws.size(), &written, nullptr);
            return;
        }
    }
#endif
    fwrite(text.data(), 1, text.size(), stream);
    fflush(stream);
}

void out_print(const CliConfig& cfg, const std::string& text) {
    if (cfg.quiet_all || cfg.quiet_mode) return;
    FILE* target = cfg.msg_to_stderr ? stderr : stdout;
    print_stream(target, text);
}

void out_println(const CliConfig& cfg, const std::string& text = "") {
    out_print(cfg, text + "\n");
}

void err_println(const CliConfig& cfg, const std::string& text) {
    if (!cfg.log_file.empty()) {
        std::ofstream lf(make_fspath(cfg.log_file), std::ios::app);
        if (lf) lf << text << "\n";
    }
    if (cfg.quiet_all) return;
    print_stream(stderr, text + "\n");
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string to_upper_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string normalize_internal_slashes(std::string s) {
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    return s;
}

std::string to_native_slashes(std::string s) {
#ifdef _WIN32
    for (char& c : s) {
        if (c == '/') c = '\\';
    }
#endif
    return s;
}

// Wildcard matching (* and ?), case-insensitive on Windows
bool wildcard_match(const std::string& pattern, const std::string& str, bool case_sensitive = false) {
    std::string p = case_sensitive ? normalize_internal_slashes(pattern)
                                   : to_lower_ascii(normalize_internal_slashes(pattern));
    std::string s = case_sensitive ? normalize_internal_slashes(str)
                                   : to_lower_ascii(normalize_internal_slashes(str));
    if (p == "*" || p == "*.*") return true;

    size_t pi = 0, si = 0;
    size_t star_idx = std::string::npos, match_idx = 0;
    while (si < s.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
            ++pi;
            ++si;
        } else if (pi < p.size() && p[pi] == '*') {
            star_idx = pi++;
            match_idx = si;
        } else if (star_idx != std::string::npos) {
            pi = star_idx + 1;
            si = ++match_idx;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool matches_entry_filters(const CliConfig& cfg, const std::string& internal_name, uint64_t size, uint64_t mtime_winft) {
    std::string base_name = internal_name;
    auto slash_pos = base_name.find_last_of('/');
    if (slash_pos != std::string::npos) base_name = base_name.substr(slash_pos + 1);

    // Exclude masks (-x)
    for (const auto& ex : cfg.exclude_masks) {
        if (wildcard_match(ex, internal_name) || wildcard_match(ex, base_name)) {
            return false;
        }
    }

    // Include masks (-n)
    if (!cfg.include_masks.empty()) {
        bool inc_ok = false;
        for (const auto& inc : cfg.include_masks) {
            if (wildcard_match(inc, internal_name) || wildcard_match(inc, base_name)) {
                inc_ok = true;
                break;
            }
        }
        if (!inc_ok) return false;
    }

    // Positional file filters (if specified for x/e/l/v/t/d/p)
    if (!cfg.file_args.empty()) {
        bool arg_ok = false;
        for (const auto& farg : cfg.file_args) {
            std::string norm_arg = normalize_internal_slashes(farg);
            if (wildcard_match(norm_arg, internal_name) ||
                wildcard_match(norm_arg, base_name) ||
                (internal_name.size() > norm_arg.size() &&
                 internal_name.compare(0, norm_arg.size(), norm_arg) == 0 &&
                 internal_name[norm_arg.size()] == '/')) {
                arg_ok = true;
                break;
            }
        }
        if (!arg_ok) return false;
    }

    if (cfg.size_less > 0 && size >= cfg.size_less) return false;
    if (cfg.size_more > 0 && size <= cfg.size_more) return false;
    if (cfg.time_after > 0 && mtime_winft < cfg.time_after) return false;
    if (cfg.time_before > 0 && mtime_winft > cfg.time_before) return false;
    if (cfg.time_newer_sec > 0) {
        uint64_t now_ft = current_win_filetime();
        uint64_t cutoff = now_ft - cfg.time_newer_sec * 10000000ULL;
        if (mtime_winft < cutoff) return false;
    }
    if (cfg.time_older_sec > 0) {
        uint64_t now_ft = current_win_filetime();
        uint64_t cutoff = now_ft - cfg.time_older_sec * 10000000ULL;
        if (mtime_winft > cutoff) return false;
    }
    return true;
}

void print_banner(const CliConfig& cfg) {
    if (cfg.quiet_copyright || cfg.quiet_all || cfg.quiet_mode) return;
    out_println(cfg, "");
    out_println(cfg, "RAR 7.01 x64 (OpenRAR Clean-Room GPLv3+)  ");
    out_println(cfg, "");
}

void print_help(const CliConfig& cfg) {
    print_banner(cfg);
    const char* help_text =
R"(用法:     rar <命令> -<开关 1> -<开关 N> <压缩文件> <文件...>
               <@列表文件...> <解压路径\>

<命令>
  a             添加文件到压缩文件
  c             添加压缩文件注释
  ch            更改压缩文件参数
  cw            将压缩文件注释写入文件
  d             从压缩文件删除文件
  e             解压文件但不包含路径
  f             刷新压缩文件中的文件
  i[par]=<str>  在压缩文件中查找字符串
  k             锁定压缩文件
  l[t[a],b]     列出压缩文件内容 [技术信息[全部], 简洁]
  m[f]          移动到压缩文件 [仅限文件]
  p             打印文件到标准输出
  r             修复压缩文件
  rc            重建丢失的卷
  rn            重命名压缩文件中的文件
  rr[N]         添加数据恢复记录
  rv[N]         创建恢复卷
  s[name|-]     转换压缩文件为自解压格式或从自解压格式转换
  t             测试压缩文件
  u             更新压缩文件中的文件
  v[t[a],b]     详细列出压缩文件内容 [技术信息[全部], 简洁]
  x             使用完整路径解压文件

<开关>
  -             停止扫描开关
  -?            显示帮助信息
  -@[+]         禁用 [启用] 文件列表
  -ac           压缩或解压后清除存档属性
  -ad[1,2]      附加压缩文件名到目标路径
  -ag[format]   使用当前日期生成压缩文件名
  -ai           忽略文件属性
  -ap<path>     设置压缩文件内部路径
  -as           同步压缩文件内容
  -c-           禁用注释显示
  -cfg-         禁用读取配置
  -cl           转换名称为小写
  -cu           转换名称为大写
  -df           压缩后删除文件
  -dr           压缩后删除文件到回收站
  -ds           禁用固实压缩文件的名称排序
  -dw           压缩后擦除文件
  -ed           不添加空目录
  -ep           从名称中排除路径
  -ep1          从名称中排除基本目录
  -ep2          展开为完整路径
  -ep3          展开路径为包含驱动器盘符的完整路径
  -ep4<path>    从名称中排除路径前缀
  -f            刷新文件
  -hp[password] 加密文件数据和标头
  -ht[b|c]      选择哈希类型 [BLAKE2,CRC32] 用于文件校验和
  -id[c,d,n,p,q] 禁用消息
  -ierr         发送所有消息到标准错误输出
  -ilog[name]   记录错误到文件
  -inul         禁用所有消息
  -iver         显示版本号
  -k            锁定压缩文件
  -kb           保留损坏的已解压文件
  -log[f][=name] 将名称写入日志文件
  -m<0..5>      设置压缩级别 (0-存储...3-默认...5-最大)
  -md<n>[k,m,g] 字典大小 (以 KB, MB 或 GB 为单位)
  -ms[ext;ext]  指定直接存储的文件类型
  -mt<threads>  设置线程数
  -n<file>      仅包含指定文件
  -n@           从标准输入读取附加包含掩码
  -n@<list>     从列表文件读取附加包含掩码
  -o[+|-]       设置覆盖模式
  -op<path>     设置解压文件的输出路径
  -or           自动重命名文件
  -p[password]  设置密码
  -qo[-|+]      添加快速打开信息 [无|强制]
  -r            递归子目录
  -r-           禁用递归
  -r0           仅使用通配符名称递归子目录
  -rr[N]        添加数据恢复记录
  -rv[N]        创建恢复卷
  -s[<N>,v[-],e] 创建固实压缩文件
  -s-           禁用固实归档
  -sc<chr>[obj] 指定字符集
  -sfx[name]    创建自解压压缩文件
  -si[name]     从标准输入 (stdin) 读取数据
  -sl<size>     处理小于指定大小的文件
  -sm<size>     处理大于指定大小的文件
  -t            压缩后测试文件
  -ta<d>        处理修改日期晚于 <d> 的文件 (YYYYMMDDHHMMSS)
  -tb<d>        处理修改日期早于 <d> 的文件 (YYYYMMDDHHMMSS)
  -tk           保留原始压缩文件时间
  -tl           设置压缩文件时间为最新文件时间
  -tn<t>        处理比 <t> 更新的文件
  -to<t>        处理比 <t> 更旧的文件
  -ts[m,c,a]    保存或恢复文件时间 (修改, 创建, 访问)
  -u            更新文件
  -v<size>[k,b] 创建指定大小的卷 (<size>*1000 [*1024, *1])
  -ver[n]       文件版本控制
  -w<path>      指定工作目录
  -x<file>      排除指定文件
  -x@           从标准输入读取要排除的文件名
  -x@<list>     排除指定列表文件中列出的文件
  -y            假设所有询问均回答“是”
  -z[file]      从文件读取压缩文件注释

<unrar-free 兼容长选项>
  --extract           解压文件 (等同于 x)
  --extract-no-paths  解压文件不包含路径 (等同于 e)
  --extract-newer     仅解压更新的文件 (等同于 -u)
  --list              列出压缩文件内容 (等同于 l)
  --print             打印文件到标准输出 (等同于 p)
  --force             覆盖已存在文件 (等同于 -o+)
  --password <pwd>    指定密码 (等同于 -p<pwd>)
  --verbose           详细输出)";
    out_println(cfg, help_text);
}

uint64_t parse_size_With_unit(const std::string& str, char default_unit = 'b') {
    if (str.empty()) return 0;
    size_t idx = 0;
    uint64_t val = 0;
    while (idx < str.size() && std::isdigit((unsigned char)str[idx])) {
        val = val * 10 + (str[idx] - '0');
        ++idx;
    }
    char unit = (idx < str.size()) ? str[idx] : default_unit;
    switch (unit) {
        case 'b': case 'B': return val;
        case 'k': return val * 1024ULL;
        case 'K': return val * 1000ULL;
        case 'm': return val * 1024ULL * 1024ULL;
        case 'M': return val * 1000ULL * 1000ULL;
        case 'g': return val * 1024ULL * 1024ULL * 1024ULL;
        case 'G': return val * 1000ULL * 1000ULL * 1000ULL;
        case 'f': return val * 1457664ULL;
        default:  return val * 1000ULL; // WinRAR default for -v<size> without suffix is *1000
    }
}

uint64_t parse_rar_date_to_winft(const std::string& dstr) {
    // Format: YYYYMMDD[HHMMSS]
    if (dstr.size() < 8) return 0;
    std::tm tm_val{};
    tm_val.tm_year = std::stoi(dstr.substr(0, 4)) - 1900;
    tm_val.tm_mon  = std::stoi(dstr.substr(4, 2)) - 1;
    tm_val.tm_mday = std::stoi(dstr.substr(6, 2));
    if (dstr.size() >= 10) tm_val.tm_hour = std::stoi(dstr.substr(8, 2));
    if (dstr.size() >= 12) tm_val.tm_min  = std::stoi(dstr.substr(10, 2));
    if (dstr.size() >= 14) tm_val.tm_sec  = std::stoi(dstr.substr(12, 2));
    tm_val.tm_isdst = -1;
    time_t t = std::mktime(&tm_val);
    if (t == (time_t)-1) return 0;
    return unix_to_win_filetime((int64_t)t, 0);
}

uint64_t parse_rar_duration_seconds(const std::string& tstr) {
    // Format: [Nd][Nh][Nm][Ns] e.g. 10d, 2h30m, 45s
    uint64_t total_sec = 0;
    uint64_t cur = 0;
    for (char c : tstr) {
        if (std::isdigit((unsigned char)c)) {
            cur = cur * 10 + (c - '0');
        } else {
            char lc = (char)std::tolower((unsigned char)c);
            if (lc == 'd') total_sec += cur * 86400ULL;
            else if (lc == 'h') total_sec += cur * 3600ULL;
            else if (lc == 'm') total_sec += cur * 60ULL;
            else if (lc == 's') total_sec += cur;
            cur = 0;
        }
    }
    total_sec += cur;
    return total_sec;
}

void read_list_file(const std::string& list_path, std::vector<std::string>& out_items) {
    std::istream* in = nullptr;
    std::ifstream fin;
    if (list_path.empty()) {
        in = &std::cin;
    } else {
        fin.open(make_fspath(list_path));
        if (!fin) return;
        in = &fin;
    }
    std::string line;
    while (std::getline(*in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) ++start;
        line = line.substr(start);
        if (!line.empty() && line.substr(0, 3) == "\xEF\xBB\xBF") line = line.substr(3);
        if (!line.empty() && line[0] != ';') {
            if (line.size() >= 2 && line.front() == '"' && line.back() == '"') {
                line = line.substr(1, line.size() - 2);
            }
            out_items.push_back(line);
        }
    }
}

void format_winft_datetime(uint64_t winft, std::string& out_date, std::string& out_time, std::string* out_full_ns = nullptr) {
    if (winft == 0) {
        out_date = "0000-00-00";
        out_time = "00:00";
        if (out_full_ns) *out_full_ns = "0000-00-00 00:00:00,0000000";
        return;
    }
    int64_t unix_sec = 0;
    uint32_t nsec = 0;
    win_filetime_to_unix(winft, unix_sec, nsec);
    time_t tt = (time_t)unix_sec;
    std::tm local_tm{};
#ifdef _WIN32
    localtime_s(&local_tm, &tt);
#else
    localtime_r(&tt, &local_tm);
#endif
    char dbuf[32], tbuf[32];
    std::snprintf(dbuf, sizeof(dbuf), "%04d-%02d-%02d",
                  local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
    std::snprintf(tbuf, sizeof(tbuf), "%02d:%02d",
                  local_tm.tm_hour, local_tm.tm_min);
    out_date = dbuf;
    out_time = tbuf;
    if (out_full_ns) {
        char fbuf[64];
        std::snprintf(fbuf, sizeof(fbuf), "%04d-%02d-%02d %02d:%02d:%02d,%07u",
                      local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday,
                      local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec, nsec / 100);
        *out_full_ns = fbuf;
    }
}

std::string format_attributes(const RarFileEntry& e) {
    char buf[8] = {'.', '.', '.', '.', '.', '.', '.', '\0'};
    if (e.is_dir || (e.attributes & 0x10)) buf[3] = 'D';
    if (e.attributes & 0x20) buf[2] = 'A';
    if (e.attributes & 0x04) buf[4] = 'S';
    if (e.attributes & 0x02) buf[5] = 'H';
    if (e.attributes & 0x01) buf[6] = 'R';
    return std::string(buf);
}

void get_file_times_and_attrs(const fs::path& p, bool is_dir,
                              uint64_t& mtime_winft, uint64_t& ctime_winft,
                              uint64_t& atime_winft, uint64_t& attrs) {
    mtime_winft = current_win_filetime();
    ctime_winft = mtime_winft;
    atime_winft = mtime_winft;
    attrs = is_dir ? 0x10 : 0x20;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) {
        attrs = fad.dwFileAttributes;
        mtime_winft = (uint64_t(fad.ftLastWriteTime.dwHighDateTime) << 32) | fad.ftLastWriteTime.dwLowDateTime;
        ctime_winft = (uint64_t(fad.ftCreationTime.dwHighDateTime) << 32) | fad.ftCreationTime.dwLowDateTime;
        atime_winft = (uint64_t(fad.ftLastAccessTime.dwHighDateTime) << 32) | fad.ftLastAccessTime.dwLowDateTime;
    }
#else
    std::error_code ec;
    auto ftime = fs::last_write_time(p, ec);
    if (!ec) {
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        mtime_winft = unix_to_win_filetime(sctp.time_since_epoch().count(), 0);
        ctime_winft = mtime_winft;
        atime_winft = mtime_winft;
    }
#endif
}

void apply_extracted_times_and_attrs(const fs::path& p, const RarFileEntry& e, const CliConfig& cfg) {
#ifdef _WIN32
    DWORD flags = e.is_dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE hFile = CreateFileW(p.c_str(), FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, flags, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ft_m{}, ft_c{}, ft_a{};
        const FILETIME* p_m = nullptr;
        const FILETIME* p_c = nullptr;
        const FILETIME* p_a = nullptr;
        if (e.mtime_winft != 0) {
            ft_m.dwLowDateTime = (DWORD)(e.mtime_winft & 0xFFFFFFFFULL);
            ft_m.dwHighDateTime = (DWORD)(e.mtime_winft >> 32);
            p_m = &ft_m;
        }
        if (e.ctime_winft != 0) {
            ft_c.dwLowDateTime = (DWORD)(e.ctime_winft & 0xFFFFFFFFULL);
            ft_c.dwHighDateTime = (DWORD)(e.ctime_winft >> 32);
            p_c = &ft_c;
        }
        if (e.atime_winft != 0) {
            ft_a.dwLowDateTime = (DWORD)(e.atime_winft & 0xFFFFFFFFULL);
            ft_a.dwHighDateTime = (DWORD)(e.atime_winft >> 32);
            p_a = &ft_a;
        }
        SetFileTime(hFile, p_c, p_a, p_m);
        CloseHandle(hFile);
    }
    if (!cfg.ignore_attributes && !e.is_dir && e.attributes != 0) {
        DWORD win_attr = (DWORD)(e.attributes & 0x27); // R, H, S, A
        if (cfg.clear_archive_attr) win_attr &= ~FILE_ATTRIBUTE_ARCHIVE;
        if (win_attr != 0) SetFileAttributesW(p.c_str(), win_attr);
    }
#else
    (void)p; (void)e; (void)cfg;
#endif
}

std::string ensure_archive_extension(const std::string& path, bool is_sfx) {
    fs::path p = make_fspath(path);
    if (p.has_extension()) return path;
    return path + (is_sfx ? ".exe" : ".rar");
}

std::string apply_ag_format(const std::string& base_path, const std::string& fmt) {
    if (fmt.empty()) return base_path;
    time_t now = std::time(nullptr);
    std::tm tm_now{};
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    // Replace YYYY, YY, MM, DD, HH, MN, SS in format string
    std::string stamp;
    size_t i = 0;
    while (i < fmt.size()) {
        auto count_char = [&](char ch) {
            size_t cnt = 0;
            while (i + cnt < fmt.size() && fmt[i + cnt] == ch) ++cnt;
            return cnt;
        };
        if (fmt[i] == 'Y') {
            size_t cnt = count_char('Y');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%04d", tm_now.tm_year + 1900);
            std::string ys(buf);
            stamp += (cnt >= 4) ? ys : ys.substr(2);
            i += cnt;
        } else if (fmt[i] == 'M') {
            size_t cnt = count_char('M');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_mon + 1);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'D') {
            size_t cnt = count_char('D');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_mday);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'H') {
            size_t cnt = count_char('H');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_hour);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'S') {
            size_t cnt = count_char('S');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_sec);
            stamp += buf;
            i += cnt;
        } else {
            stamp.push_back(fmt[i++]);
        }
    }
    fs::path p = make_fspath(base_path);
    std::string ext = fspath_to_utf8(p.extension());
    std::string stem = fspath_to_utf8(p.parent_path() / p.stem());
    return stem + stamp + ext;
}

std::string compute_internal_name(const CliConfig& cfg, const fs::path& full_path, const fs::path& base_arg_path) {
    std::string name;
    if (cfg.ep_mode == 0) {
        // -ep: exclude all paths, store filename only
        name = fspath_to_utf8(full_path.filename());
    } else if (cfg.ep_mode == 2 || cfg.ep_mode == 3) {
        // -ep2 / -ep3: full path
        name = normalize_internal_slashes(fspath_to_utf8(full_path));
        if (cfg.ep_mode == 2 && name.size() >= 2 && name[1] == ':') {
            name = name.substr(2);
            while (!name.empty() && name.front() == '/') name.erase(name.begin());
        } else if (cfg.ep_mode == 3 && name.size() >= 2 && name[1] == ':') {
            name[1] = '_';
        }
    } else {
        // -ep1 (default): strip parent of base_arg_path
        fs::path parent = base_arg_path.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            fs::path rel = fs::relative(full_path, parent, ec);
            if (!ec && !rel.empty() && fspath_to_utf8(rel).substr(0, 2) != "..") {
                name = normalize_internal_slashes(fspath_to_utf8(rel));
            } else {
                name = normalize_internal_slashes(fspath_to_utf8(full_path.filename()));
            }
        } else {
            name = normalize_internal_slashes(fspath_to_utf8(full_path));
            if (name.size() >= 2 && name[1] == ':') {
                name = name.substr(2);
            }
            while (name.substr(0, 2) == "./") name = name.substr(2);
        }
    }

    if (!cfg.ep4_prefix.empty()) {
        std::string pfx = normalize_internal_slashes(cfg.ep4_prefix);
        if (!pfx.empty() && pfx.back() != '/') pfx.push_back('/');
        if (name.size() > pfx.size() &&
            to_lower_ascii(name.substr(0, pfx.size())) == to_lower_ascii(pfx)) {
            name = name.substr(pfx.size());
        }
    }

    if (!cfg.ap_prefix.empty()) {
        std::string ap = normalize_internal_slashes(cfg.ap_prefix);
        while (!ap.empty() && ap.back() == '/') ap.pop_back();
        if (!ap.empty()) name = ap + "/" + name;
    }

    if (cfg.case_convert == 1) name = to_lower_ascii(name);
    else if (cfg.case_convert == 2) name = to_upper_ascii(name);

    return normalize_internal_slashes(name);
}

bool parse_switch(const std::string& sw_raw, CliConfig& cfg, const std::vector<std::string>& args, size_t& arg_idx) {
    // Handle GNU long options (unrar-free compatibility)
    if (sw_raw.size() >= 2 && sw_raw[0] == '-' && sw_raw[1] == '-') {
        std::string lopt = sw_raw.substr(2);
        if (lopt.empty()) return false; // "--" stops switch scanning
        if (lopt == "help") { cfg.show_help = true; return true; }
        if (lopt == "version") { cfg.show_version = true; return true; }
        if (lopt == "extract") { if (cfg.command.empty()) cfg.command = "x"; return true; }
        if (lopt == "extract-no-paths") {
            if (cfg.command.empty()) cfg.command = "e";
            cfg.ep_mode = 0;
            return true;
        }
        if (lopt == "extract-newer") { cfg.command = (cfg.command.empty() ? "x" : cfg.command); return true; }
        if (lopt == "list") { if (cfg.command.empty()) cfg.command = "l"; return true; }
        if (lopt == "print") { if (cfg.command.empty()) cfg.command = "p"; return true; }
        if (lopt == "force") { cfg.overwrite_mode = 1; cfg.assume_yes = true; return true; }
        if (lopt == "verbose") { if (cfg.command == "l") cfg.command = "v"; return true; }
        if (lopt == "password") {
            if (arg_idx + 1 < args.size()) cfg.arch_opts.password = args[++arg_idx];
            return true;
        }
        if (lopt.substr(0, 9) == "password=") {
            cfg.arch_opts.password = lopt.substr(9);
            return true;
        }
        if (lopt == "outfile") {
            if (arg_idx + 1 < args.size()) cfg.log_file = args[++arg_idx];
            return true;
        }
        return true;
    }

    std::string sw = sw_raw.substr(1);
    if (sw.empty() || sw == "-") return false; // "-" stops switch scanning
    std::string sw_low = to_lower_ascii(sw);

    if (sw_low == "?" || sw_low == "h") { cfg.show_help = true; return true; }
    if (sw_low == "iver" || sw == "V") { cfg.show_version = true; return true; }
    if (sw_low == "y") { cfg.assume_yes = true; cfg.overwrite_mode = 1; return true; }
    if (sw_low == "o+" || sw_low == "o") { cfg.overwrite_mode = 1; return true; }
    if (sw_low == "o-") { cfg.overwrite_mode = -1; return true; }
    if (sw_low == "or") { cfg.auto_rename = true; return true; }
    if (sw_low == "r") { cfg.recurse = true; cfg.disable_recurse = false; return true; }
    if (sw_low == "r0") { cfg.recurse_wildcard = true; return true; }
    if (sw_low == "r-") { cfg.disable_recurse = true; cfg.recurse = false; return true; }
    if (sw_low == "k") { cfg.arch_opts.lock_archive = true; return true; }
    if (sw_low == "kb") { cfg.keep_broken = true; return true; }
    if (sw_low == "t") { cfg.test_after_archive = true; return true; }
    if (sw_low == "df" || sw_low == "dr" || sw_low == "dw") { cfg.delete_after = true; return true; }
    if (sw_low == "ed") { cfg.no_empty_dirs = true; return true; }
    if (sw_low == "ac") { cfg.clear_archive_attr = true; return true; }
    if (sw_low == "ai") { cfg.ignore_attributes = true; return true; }
    if (sw_low == "cl") { cfg.case_convert = 1; return true; }
    if (sw_low == "cu") { cfg.case_convert = 2; return true; }
    if (sw_low == "ds") { cfg.disable_sort = true; return true; }
    if (sw_low == "as") { cfg.sync_archive = true; return true; }
    if (sw_low == "tk") { cfg.keep_archive_time = true; return true; }
    if (sw_low == "tl") { cfg.latest_archive_time = true; return true; }
    if (sw_low == "c-") { cfg.disable_comments = true; return true; }
    if (sw_low == "cfg-") { return true; }
    if (sw_low == "inul") { cfg.quiet_all = true; return true; }
    if (sw_low == "ierr") { cfg.msg_to_stderr = true; return true; }
    if (sw_low.substr(0, 2) == "id") {
        for (size_t i = 2; i < sw_low.size(); ++i) {
            if (sw_low[i] == 'c') cfg.quiet_copyright = true;
            else if (sw_low[i] == 'd') cfg.quiet_done = true;
            else if (sw_low[i] == 'n') cfg.quiet_names = true;
            else if (sw_low[i] == 'p') cfg.quiet_percent = true;
            else if (sw_low[i] == 'q') cfg.quiet_mode = true;
        }
        return true;
    }
    if (sw_low.substr(0, 4) == "ilog") {
        cfg.log_file = sw.size() > 4 ? sw.substr(4) : "rar.log";
        return true;
    }
    if (sw_low.substr(0, 3) == "log") {
        auto eq = sw.find('=');
        cfg.log_file = (eq != std::string::npos) ? sw.substr(eq + 1) : "rar.log";
        return true;
    }

    // Path modes (-ep, -ep1, -ep2, -ep3, -ep4<path>)
    if (sw_low == "ep") { cfg.ep_mode = 0; return true; }
    if (sw_low == "ep1") { cfg.ep_mode = 1; return true; }
    if (sw_low == "ep2") { cfg.ep_mode = 2; return true; }
    if (sw_low == "ep3") { cfg.ep_mode = 3; return true; }
    if (sw_low.substr(0, 3) == "ep4") { cfg.ep4_prefix = sw.substr(3); return true; }
    if (sw_low.substr(0, 2) == "ap") { cfg.ap_prefix = sw.substr(2); return true; }
    if (sw_low.substr(0, 2) == "op") { cfg.op_path = sw.substr(2); return true; }
    if (sw_low == "ad" || sw_low == "ad1") { cfg.append_arch_dir = 1; return true; }
    if (sw_low == "ad2") { cfg.append_arch_dir = 2; return true; }
    if (sw_low.substr(0, 1) == "w" && sw.size() > 1) { cfg.work_dir = sw.substr(1); return true; }

    // Compression level -m0..5 and dictionary -md<size> and store extensions -ms and threads -mt
    if (sw_low.size() == 2 && sw_low[0] == 'm' && sw_low[1] >= '0' && sw_low[1] <= '5') {
        cfg.arch_opts.method = sw_low[1] - '0';
        return true;
    }
    if (sw_low.substr(0, 2) == "md") {
        std::string dstr = sw_low.substr(2);
        if (!dstr.empty() && dstr[0] == 'x') dstr = dstr.substr(1);
        if (!dstr.empty() && dstr[0] == '=') dstr = dstr.substr(1);
        if (!dstr.empty()) {
            // Check letter codes a..j or numeric size
            if (dstr.size() == 1 && dstr[0] >= 'a' && dstr[0] <= 'j') {
                int idx = dstr[0] - 'a';
                cfg.arch_opts.dict_bits = std::max(0, idx - 1);
            } else {
                uint64_t bytes = parse_size_With_unit(dstr, 'm');
                if (bytes < 128 * 1024ULL && bytes <= 1024) {
                    // Bare number <= 1024 in -md<N> means MB in RAR5 (unless >= 128 where 128/256/512 = KB)
                    if (bytes >= 128) bytes *= 1024ULL;
                    else bytes *= 1024ULL * 1024ULL;
                }
                int bits = 0;
                uint64_t sz = 128 * 1024ULL;
                while (sz < bytes && bits < 15) { sz <<= 1; ++bits; }
                cfg.arch_opts.dict_bits = bits;
            }
        }
        return true;
    }
    if (sw_low.substr(0, 2) == "ms") {
        std::string exts = sw_low.substr(2);
        if (exts.empty()) exts = "rar;zip;7z;gz;bz2;xz;jpg;jpeg;png;mp3;mp4;mkv";
        std::stringstream ss(exts);
        std::string item;
        while (std::getline(ss, item, ';')) {
            if (!item.empty()) {
                if (item.front() == '.') item.erase(item.begin());
                cfg.store_exts.push_back(item);
            }
        }
        return true;
    }
    if (sw_low.substr(0, 2) == "mt" || sw_low.substr(0, 2) == "mc") {
        return true;
    }

    // Solid switches (-s, -s-, -se, -sv, -sv-)
    if (sw_low == "s-") { cfg.arch_opts.solid = false; return true; }
    if (sw_low == "s" || sw_low == "se" || sw_low == "sv" || sw_low == "sv-" ||
        (sw_low.size() > 1 && sw_low[0] == 's' && std::isdigit((unsigned char)sw_low[1]))) {
        cfg.arch_opts.solid = true;
        return true;
    }

    // Hash type (-htb, -htc)
    if (sw_low == "htb") { cfg.arch_opts.use_blake2sp = true; return true; }
    if (sw_low == "htc") { cfg.arch_opts.use_blake2sp = false; return true; }

    // Password (-p[pwd], -hp[pwd])
    if (sw_low.substr(0, 2) == "hp") {
        cfg.arch_opts.encrypt_headers = true;
        cfg.arch_opts.password = sw.substr(2);
        return true;
    }
    if (sw_low[0] == 'p' || sw[0] == 'P') {
        cfg.arch_opts.password = sw.substr(1);
        return true;
    }

    // Recovery record (-rr[N], -rv[N])
    if (sw_low.substr(0, 2) == "rr" || sw_low.substr(0, 2) == "rv") {
        std::string rstr = sw_low.substr(2);
        int pct = 3;
        if (!rstr.empty()) {
            pct = std::max(1, std::atoi(rstr.c_str()));
        }
        cfg.arch_opts.recovery_percent = pct;
        return true;
    }

    // Quick open (-qo[-|+])
    if (sw_low.substr(0, 2) == "qo") {
        cfg.arch_opts.quick_open = (sw_low != "qo-");
        return true;
    }

    // SFX (-sfx[name])
    if (sw_low.substr(0, 3) == "sfx") {
        cfg.create_sfx = true;
        cfg.sfx_stub_name = sw.substr(3);
        return true;
    }

    // Volume size (-v<size>[u])
    if (sw_low[0] == 'v' && sw_low.substr(0, 3) != "ver") {
        std::string vstr = sw.substr(1);
        if (!vstr.empty()) {
            cfg.arch_opts.volume_size = parse_size_With_unit(vstr, '\0');
        }
        return true;
    }

    // File version control (-ver[n])
    if (sw_low.substr(0, 3) == "ver") {
        cfg.version_control = true;
        if (sw.size() > 3) cfg.max_versions = std::atoi(sw.substr(3).c_str());
        return true;
    }

    // Comment from file (-z[file])
    if (sw_low[0] == 'z') {
        cfg.comment_file = sw.substr(1);
        return true;
    }

    // Read from stdin (-si[name])
    if (sw_low.substr(0, 2) == "si") {
        cfg.read_from_stdin = true;
        cfg.stdin_name = sw.size() > 2 ? sw.substr(2) : "stdin";
        return true;
    }

    // Archive name timestamp (-ag[format])
    if (sw_low.substr(0, 2) == "ag") {
        cfg.ag_format = sw.size() > 2 ? sw.substr(2) : "YYYYMMDDHHMMSS";
        return true;
    }

    // Time saving (-ts[m,c,a])
    if (sw_low.substr(0, 2) == "ts") {
        for (size_t i = 2; i < sw_low.size(); ++i) {
            if (sw_low[i] == 'c') cfg.arch_opts.save_ctime = (i + 1 >= sw_low.size() || sw_low[i + 1] != '-');
            if (sw_low[i] == 'a') cfg.arch_opts.save_atime = (i + 1 >= sw_low.size() || sw_low[i + 1] != '-');
        }
        return true;
    }

    // Size & time filters (-sl, -sm, -ta, -tb, -tn, -to)
    if (sw_low.substr(0, 2) == "sl") { cfg.size_less = parse_size_With_unit(sw.substr(2), 'b'); return true; }
    if (sw_low.substr(0, 2) == "sm") { cfg.size_more = parse_size_With_unit(sw.substr(2), 'b'); return true; }
    if (sw_low.substr(0, 2) == "ta") { cfg.time_after = parse_rar_date_to_winft(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "tb") { cfg.time_before = parse_rar_date_to_winft(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "tn") { cfg.time_newer_sec = parse_rar_duration_seconds(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "to") { cfg.time_older_sec = parse_rar_duration_seconds(sw.substr(2)); return true; }

    // Include & Exclude masks (-n, -n@, -x, -x@)
    if (sw_low.substr(0, 2) == "n@") {
        read_list_file(sw.substr(2), cfg.include_masks);
        return true;
    }
    if (sw_low[0] == 'n' && sw.size() > 1) {
        cfg.include_masks.push_back(sw.substr(1));
        return true;
    }
    if (sw_low.substr(0, 2) == "x@") {
        read_list_file(sw.substr(2), cfg.exclude_masks);
        return true;
    }
    if (sw_low[0] == 'x' && sw.size() > 1) {
        cfg.exclude_masks.push_back(sw.substr(1));
        return true;
    }

    return true;
}

bool is_known_command(const std::string& token, CliConfig& cfg) {
    std::string low = to_lower_ascii(token);
    if (low == "a" || low == "c" || low == "ch" || low == "cw" || low == "d" ||
        low == "e" || low == "f" || low == "k" || low == "l" || low == "lt" ||
        low == "lta" || low == "lb" || low == "m" || low == "mf" || low == "p" ||
        low == "r" || low == "rc" || low == "rn" || low == "s-" || low == "t" ||
        low == "u" || low == "v" || low == "vt" || low == "vta" || low == "vb" ||
        low == "x") {
        cfg.command = low;
        if (low == "m") cfg.delete_after = true;
        if (low == "mf") { cfg.delete_after = true; cfg.move_files_only = true; }
        return true;
    }
    if (low.substr(0, 2) == "rr" && (low.size() == 2 || std::isdigit((unsigned char)low[2]))) {
        cfg.command = "rr";
        cfg.arch_opts.recovery_percent = (low.size() > 2) ? std::max(1, std::atoi(low.substr(2).c_str())) : 3;
        return true;
    }
    if (low.substr(0, 2) == "rv" && (low.size() == 2 || std::isdigit((unsigned char)low[2]))) {
        cfg.command = "rv";
        cfg.arch_opts.recovery_percent = (low.size() > 2) ? std::max(1, std::atoi(low.substr(2).c_str())) : 3;
        return true;
    }
    if (low[0] == 's' && low != "s-") {
        cfg.command = "s";
        if (token.size() > 1) cfg.sfx_stub_name = token.substr(1);
        return true;
    }
    if (low[0] == 'i') {
        auto eq = token.find('=');
        if (eq != std::string::npos) {
            cfg.command = "i";
            cfg.find_params = to_lower_ascii(token.substr(1, eq - 1));
            cfg.find_str = token.substr(eq + 1);
            return true;
        }
    }
    return false;
}

// ============================================================================
// Command Implementations
// ============================================================================

int cmd_list(const CliConfig& cfg) {
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg + " (" + arch_path + ")");
        return (int)rc;
    }

    bool bare = (cfg.command == "lb" || cfg.command == "vb");
    bool tech = (cfg.command == "lt" || cfg.command == "lta" || cfg.command == "vt" || cfg.command == "vta");
    bool verbose = (cfg.command[0] == 'v');

    if (bare) {
        for (const auto& e : arch.entries) {
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
            out_println(cfg, to_native_slashes(e.name));
        }
        return RAR_EXIT_SUCCESS;
    }

    print_banner(cfg);
    if (!cfg.disable_comments && !arch.comment.empty()) {
        out_println(cfg, arch.comment);
        out_println(cfg, "");
    }

    out_println(cfg, "压缩文件: " + to_native_slashes(arch_path));
    std::string details = "详情: RAR 5";
    if (arch.is_solid) details += ", 固实";
    if (arch.has_recovery) details += ", 恢复记录";
    if (arch.is_locked) details += ", 锁定";
    if (arch.headers_encrypted) details += ", 加密标头";
    if (!arch.sfx_stub.empty()) details += ", 自解压";
    if (arch.is_volume) details += ", 卷";
    out_println(cfg, details);
    out_println(cfg, "");

    if (tech) {
        for (const auto& e : arch.entries) {
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
            out_println(cfg, "        名称: " + to_native_slashes(e.name));
            out_println(cfg, std::string("        类型: ") + (e.is_dir ? "目录" : "文件"));
            if (!e.is_dir) {
                out_println(cfg, "        大小: " + std::to_string(e.unpacked_size));
                out_println(cfg, "  打包后大小: " + std::to_string(e.packed_size));
                int ratio = (e.unpacked_size > 0)
                                ? (int)((e.packed_size * 100ULL) / e.unpacked_size)
                                : 0;
                out_println(cfg, "      压缩率: " + std::to_string(ratio) + "%");
            }
            std::string d_str, t_str, full_ns;
            if (e.mtime_winft != 0) {
                format_winft_datetime(e.mtime_winft, d_str, t_str, &full_ns);
                out_println(cfg, "    修改时间: " + full_ns);
            }
            if (e.ctime_winft != 0) {
                format_winft_datetime(e.ctime_winft, d_str, t_str, &full_ns);
                out_println(cfg, "    创建时间: " + full_ns);
            }
            if (e.atime_winft != 0) {
                format_winft_datetime(e.atime_winft, d_str, t_str, &full_ns);
                out_println(cfg, "    访问时间: " + full_ns);
            }
            out_println(cfg, "        属性: " + format_attributes(e));
            if (e.has_blake2sp) {
                std::ostringstream hs;
                hs << std::hex << std::setfill('0');
                for (int i = 0; i < 32; ++i) hs << std::setw(2) << (int)e.blake2sp[i];
                out_println(cfg, "    BLAKE2sp: " + hs.str());
            } else if (e.has_crc32) {
                char cbuf[16];
                std::snprintf(cbuf, sizeof(cbuf), "%08X", e.crc32);
                out_println(cfg, std::string("       CRC32: ") + cbuf);
            }
            out_println(cfg, std::string("     主机 OS: ") + (e.host_os == HOST5_WINDOWS ? "Windows" : "Unix"));
            uint64_t dict_kb = 128ULL << e.dict_bits;
            std::string dict_str = (dict_kb >= 1024) ? (std::to_string(dict_kb / 1024) + "m") : (std::to_string(dict_kb) + "k");
            out_println(cfg, "        压缩: RAR 5.0(v50) -m" + std::to_string(e.comp_method) +
                             " -md=" + dict_str + (e.solid ? " 固实" : ""));
            if (e.encrypted || arch.headers_encrypted) {
                out_println(cfg, "        密码: 是 (AES-256)");
            }
            out_println(cfg, "");
        }
        return RAR_EXIT_SUCCESS;
    }

    if (verbose) {
        out_println(cfg, " 属性            大小    已压缩  比率   日期       时间     校验和   名称");
        out_println(cfg, "----------- ---------  -------- ----- ---------- -----  --------  ----");
    } else {
        out_println(cfg, " 属性            大小    日期       时间   名称");
        out_println(cfg, "----------- ---------  ---------- -----  ----");
    }

    uint64_t total_unp = 0;
    uint64_t total_pck = 0;
    size_t count = 0;

    for (const auto& e : arch.entries) {
        if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
        std::string attr_s = format_attributes(e);
        if (e.encrypted || arch.headers_encrypted) attr_s = "*" + attr_s;
        else attr_s = " " + attr_s;

        std::string d_str, t_str;
        format_winft_datetime(e.mtime_winft, d_str, t_str);
        std::string disp_name = to_native_slashes(e.name);
        if (e.has_version && cfg.version_control) {
            disp_name += ";" + std::to_string(e.version_num);
        }

        if (verbose) {
            int ratio = (e.unpacked_size > 0)
                            ? (int)((e.packed_size * 100ULL) / e.unpacked_size)
                            : 0;
            char cbuf[16];
            if (e.has_crc32) std::snprintf(cbuf, sizeof(cbuf), "%08X", e.crc32);
            else if (e.has_blake2sp) std::snprintf(cbuf, sizeof(cbuf), "%02x%02x%02x%02x", e.blake2sp[0], e.blake2sp[1], e.blake2sp[2], e.blake2sp[3]);
            else std::snprintf(cbuf, sizeof(cbuf), "        ");

            char line[1024];
            std::snprintf(line, sizeof(line), "%-11s %9llu  %8llu %4d%% %10s %5s  %8s  %s",
                          attr_s.c_str(),
                          (unsigned long long)e.unpacked_size,
                          (unsigned long long)e.packed_size,
                          ratio,
                          d_str.c_str(), t_str.c_str(), cbuf, disp_name.c_str());
            out_println(cfg, line);
        } else {
            char line[1024];
            std::snprintf(line, sizeof(line), "%-11s %9llu  %10s %5s  %s",
                          attr_s.c_str(),
                          (unsigned long long)e.unpacked_size,
                          d_str.c_str(), t_str.c_str(), disp_name.c_str());
            out_println(cfg, line);
        }

        total_unp += e.unpacked_size;
        total_pck += e.packed_size;
        ++count;
    }

    if (verbose) {
        out_println(cfg, "----------- ---------  -------- ----- ---------- -----  --------  ----");
        int total_ratio = (total_unp > 0) ? (int)((total_pck * 100ULL) / total_unp) : 0;
        char sline[256];
        std::snprintf(sline, sizeof(sline), "            %9llu  %8llu %4d%%                             %zu",
                      (unsigned long long)total_unp, (unsigned long long)total_pck, total_ratio, count);
        out_println(cfg, sline);
    } else {
        out_println(cfg, "----------- ---------  ---------- -----  ----");
        char sline[256];
        std::snprintf(sline, sizeof(sline), "            %9llu                    %zu",
                      (unsigned long long)total_unp, count);
        out_println(cfg, sline);
    }

    return RAR_EXIT_SUCCESS;
}

int cmd_test(const CliConfig& cfg) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)rc;
    }

    if (!cfg.disable_comments && !arch.comment.empty()) {
        out_println(cfg, arch.comment);
        out_println(cfg, "");
    }

    out_println(cfg, "正在测试压缩文件 " + to_native_slashes(arch_path));
    out_println(cfg, "");

    Rar5Decompressor decomp;
    int err_count = 0;
    for (size_t i = 0; i < arch.entries.size(); ++i) {
        const auto& e = arch.entries[i];
        bool selected = matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft);
        if (!selected && !arch.is_solid) continue;

        std::vector<uint8_t> out_data;
        std::string extr_err;
        RarExitCode erc = arch.extract_entry(i, cfg.arch_opts.password, decomp, out_data, &extr_err);
        if (!selected) continue;

        if (erc == RAR_EXIT_SUCCESS) {
            if (!cfg.quiet_names) {
                out_println(cfg, "正在测试     " + to_native_slashes(e.name) + "                                                   完成");
            }
        } else {
            err_println(cfg, "测试失败     " + to_native_slashes(e.name) + ": " + extr_err);
            ++err_count;
        }
    }

    if (err_count == 0) {
        if (!cfg.quiet_done) out_println(cfg, "全部正常");
        return RAR_EXIT_SUCCESS;
    } else {
        err_println(cfg, "总共错误: " + std::to_string(err_count));
        return RAR_EXIT_CRC_ERROR;
    }
}

int cmd_extract_or_print(const CliConfig& cfg, const std::string& self_sfx_path = "") {
    bool is_print = (cfg.command == "p");
    bool full_paths = (cfg.command == "x") && (cfg.ep_mode != 0);

    if (!is_print) print_banner(cfg);

    std::string arch_path = self_sfx_path.empty()
                                ? ensure_archive_extension(cfg.archive_path, false)
                                : self_sfx_path;
    if (self_sfx_path.empty() && !fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }

    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)rc;
    }

    if (!is_print) {
        if (!cfg.disable_comments && !arch.comment.empty()) {
            out_println(cfg, arch.comment);
            out_println(cfg, "");
        }
        out_println(cfg, "正在从 " + to_native_slashes(arch_path) + " 解压");
        out_println(cfg, "");
    }

    fs::path base_out = cfg.op_path.empty() ? make_fspath(cfg.dest_dir) : make_fspath(cfg.op_path);
    if (cfg.append_arch_dir == 1 || cfg.append_arch_dir == 2) {
        base_out /= make_fspath(arch_path).stem();
    }

#ifdef _WIN32
    if (is_print) {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#endif

    Rar5Decompressor decomp;
    int extracted_count = 0;

    for (size_t i = 0; i < arch.entries.size(); ++i) {
        const auto& e = arch.entries[i];
        bool selected = matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft);
        if (!selected && !arch.is_solid) continue;

        std::vector<uint8_t> out_data;
        std::string extr_err;
        RarExitCode erc = arch.extract_entry(i, cfg.arch_opts.password, decomp, out_data, &extr_err);
        if (!selected) continue;

        if (erc != RAR_EXIT_SUCCESS && !cfg.keep_broken) {
            err_println(cfg, "解压错误 " + to_native_slashes(e.name) + ": " + extr_err);
            return (int)erc;
        }

        if (is_print) {
            if (!e.is_dir && !out_data.empty()) {
                fwrite(out_data.data(), 1, out_data.size(), stdout);
                fflush(stdout);
            }
            ++extracted_count;
            continue;
        }

        // Compute output relative path
        std::string rel_name = e.name;
        if (!full_paths) {
            auto slash = rel_name.find_last_of('/');
            if (slash != std::string::npos) rel_name = rel_name.substr(slash + 1);
        }
        if (cfg.case_convert == 1) rel_name = to_lower_ascii(rel_name);
        else if (cfg.case_convert == 2) rel_name = to_upper_ascii(rel_name);

        // Sanitize any path traversal ("..") components
        fs::path rel_path;
        for (const auto& part : make_fspath(rel_name)) {
            std::string ps = fspath_to_utf8(part);
            if (ps == ".." || ps == "." || ps.find(':') != std::string::npos) continue;
            rel_path /= part;
        }
        if (rel_path.empty()) continue;

        fs::path out_path = base_out.empty() ? rel_path : (base_out / rel_path);

        if (e.is_dir) {
            if (full_paths) {
                std::error_code ec;
                fs::create_directories(out_path, ec);
                apply_extracted_times_and_attrs(out_path, e, cfg);
                if (!cfg.quiet_names) {
                    out_println(cfg, "正在创建    " + fspath_to_utf8(out_path) + "                                                     完成");
                }
            }
            continue;
        }

        if (out_path.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(out_path.parent_path(), ec);
        }

        if (fs::exists(out_path)) {
            if (cfg.overwrite_mode == -1) {
                continue; // -o- skip existing
            }
            if (cfg.auto_rename) {
                // -or auto-rename to filename(1).ext
                fs::path parent = out_path.parent_path();
                std::string stem = fspath_to_utf8(out_path.stem());
                std::string ext = fspath_to_utf8(out_path.extension());
                int idx = 1;
                while (fs::exists(out_path)) {
                    out_path = parent / make_fspath(stem + "(" + std::to_string(idx++) + ")" + ext);
                }
            }
        }

        std::ofstream fout(out_path, std::ios::binary | std::ios::trunc);
        if (!fout) {
            err_println(cfg, "无法创建文件 " + fspath_to_utf8(out_path));
            return RAR_EXIT_CREATE_ERROR;
        }
        if (!out_data.empty()) {
            fout.write(reinterpret_cast<const char*>(out_data.data()), (std::streamsize)out_data.size());
        }
        fout.close();

        apply_extracted_times_and_attrs(out_path, e, cfg);

        if (!cfg.quiet_names) {
            out_println(cfg, "正在解压    " + fspath_to_utf8(out_path) + "                                                    完成");
        }
        ++extracted_count;
    }

    if (!is_print) {
        if (extracted_count == 0 && !arch.entries.empty()) {
            out_println(cfg, "没有文件可解压");
        } else if (!cfg.quiet_done) {
            out_println(cfg, "全部正常");
        }
    }
    return RAR_EXIT_SUCCESS;
}

int cmd_add_or_update(const CliConfig& cfg, const std::string& self_exe_path) {
    print_banner(cfg);

    std::string raw_arch_path = cfg.archive_path;
    if (!cfg.ag_format.empty()) {
        raw_arch_path = apply_ag_format(raw_arch_path, cfg.ag_format);
    }
    std::string arch_path = ensure_archive_extension(raw_arch_path, cfg.create_sfx);

    RarArchive arch;
    bool updating_existing = false;
    if (fs::exists(make_fspath(arch_path))) {
        std::string err_msg;
        RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
        if (rc != RAR_EXIT_SUCCESS) {
            err_println(cfg, "错误: " + err_msg);
            return (int)rc;
        }
        if (arch.is_locked) {
            err_println(cfg, "错误: 压缩文件已锁定，无法修改");
            return RAR_EXIT_LOCKED;
        }
        updating_existing = true;
    }

    if (cfg.create_sfx && arch.sfx_stub.empty()) {
        std::string stub_src = cfg.sfx_stub_name.empty() ? self_exe_path : cfg.sfx_stub_name;
        arch.sfx_stub = RarArchive::create_default_sfx_stub(stub_src);
    }

    if (!cfg.comment_file.empty()) {
        out_println(cfg, "正在从 " + cfg.comment_file + " 读取注释");
        std::ifstream cf(make_fspath(cfg.comment_file), std::ios::binary);
        if (cf) {
            arch.comment.assign((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
        }
    }

    if (updating_existing) {
        out_println(cfg, "正在更新压缩文件 " + to_native_slashes(arch_path));
    } else if (cfg.create_sfx) {
        out_println(cfg, "正在创建自解压压缩文件 " + to_native_slashes(arch_path));
    } else {
        out_println(cfg, "正在创建压缩文件 " + to_native_slashes(arch_path));
    }
    out_println(cfg, "");

    struct CandidateFile {
        fs::path    disk_path;
        std::string internal_name;
        bool        is_dir = false;
        uint64_t    size = 0;
        uint64_t    mtime_winft = 0;
        uint64_t    ctime_winft = 0;
        uint64_t    atime_winft = 0;
        uint64_t    attrs = 0x20;
    };
    std::vector<CandidateFile> candidates;
    std::vector<fs::path> paths_to_delete_after;

    // Handle -si[name] (read from stdin)
    if (cfg.read_from_stdin) {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        std::vector<uint8_t> stdin_buf;
        uint8_t chunk[16384];
        while (size_t n = fread(chunk, 1, sizeof(chunk), stdin)) {
            stdin_buf.insert(stdin_buf.end(), chunk, chunk + n);
        }
        Rar5Compressor comp;
        comp.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
        uint64_t now_ft = current_win_filetime();
        arch.add_entry_from_memory(cfg.stdin_name, stdin_buf.data(), stdin_buf.size(),
                                   false, 0x20, now_ft, now_ft, now_ft,
                                   cfg.arch_opts, comp, false);
        if (!cfg.quiet_names) {
            out_println(cfg, "正在添加    " + cfg.stdin_name + "                                                    完成");
        }
    } else {
        // Expand file_args and @listfiles
        std::vector<std::string> raw_inputs = cfg.file_args;
        if (raw_inputs.empty()) raw_inputs.push_back("*");

        std::vector<std::string> expanded_args;
        for (const auto& arg : raw_inputs) {
            if (!arg.empty() && arg[0] == '@' && !fs::exists(make_fspath(arg))) {
                read_list_file(arg.substr(1), expanded_args);
            } else {
                expanded_args.push_back(arg);
            }
        }

        auto add_candidate = [&](const fs::path& p, const fs::path& base_arg) {
            std::error_code ec;
            // Avoid adding the archive itself
            if (fs::exists(make_fspath(arch_path), ec) && fs::equivalent(p, make_fspath(arch_path), ec)) {
                return;
            }
            bool is_d = fs::is_directory(p, ec);
            if (is_d && cfg.no_empty_dirs) {
                if (fs::is_empty(p, ec)) return;
            }
            uint64_t sz = is_d ? 0 : (uint64_t)fs::file_size(p, ec);
            uint64_t m_ft = 0, c_ft = 0, a_ft = 0, attrs = 0;
            get_file_times_and_attrs(p, is_d, m_ft, c_ft, a_ft, attrs);

            std::string int_name = compute_internal_name(cfg, p, base_arg);
            if (int_name.empty()) return;

            // Check filters (excluding file_args since file_args are the inputs here)
            CliConfig filter_cfg = cfg;
            filter_cfg.file_args.clear();
            if (!matches_entry_filters(filter_cfg, int_name, sz, m_ft)) return;

            CandidateFile cf;
            cf.disk_path = p;
            cf.internal_name = int_name;
            cf.is_dir = is_d;
            cf.size = sz;
            cf.mtime_winft = m_ft;
            cf.ctime_winft = cfg.arch_opts.save_ctime ? c_ft : 0;
            cf.atime_winft = cfg.arch_opts.save_atime ? a_ft : 0;
            cf.attrs = cfg.ignore_attributes ? (is_d ? 0x10 : 0x20) : attrs;
            candidates.push_back(cf);
        };

        for (const auto& arg : expanded_args) {
            fs::path p = make_fspath(arg);
            bool has_wild = (arg.find('*') != std::string::npos || arg.find('?') != std::string::npos);

            if (!has_wild && fs::exists(p)) {
                if (fs::is_directory(p)) {
                    add_candidate(p, p);
                    if (!cfg.disable_recurse) {
                        std::error_code ec;
                        for (auto it = fs::recursive_directory_iterator(p, ec);
                             it != fs::recursive_directory_iterator(); it.increment(ec)) {
                            add_candidate(it->path(), p);
                        }
                    }
                } else {
                    add_candidate(p, p);
                }
            } else {
                // Wildcard expansion
                fs::path search_dir = p.parent_path();
                if (search_dir.empty()) search_dir = ".";
                std::string mask = fspath_to_utf8(p.filename());
                std::error_code ec;
                if (cfg.recurse || cfg.recurse_wildcard) {
                    for (auto it = fs::recursive_directory_iterator(search_dir, ec);
                         it != fs::recursive_directory_iterator(); it.increment(ec)) {
                        std::string fname = fspath_to_utf8(it->path().filename());
                        if (wildcard_match(mask, fname)) {
                            add_candidate(it->path(), search_dir / "dummy");
                        }
                    }
                } else {
                    for (auto it = fs::directory_iterator(search_dir, ec);
                         it != fs::directory_iterator(); it.increment(ec)) {
                        std::string fname = fspath_to_utf8(it->path().filename());
                        if (wildcard_match(mask, fname)) {
                            add_candidate(it->path(), search_dir / "dummy");
                            if (fs::is_directory(it->path(), ec) && !cfg.disable_recurse) {
                                for (auto rit = fs::recursive_directory_iterator(it->path(), ec);
                                     rit != fs::recursive_directory_iterator(); rit.increment(ec)) {
                                    add_candidate(rit->path(), search_dir / "dummy");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort candidates for solid archives (by extension unless -ds)
    if (cfg.arch_opts.solid && !cfg.disable_sort) {
        std::sort(candidates.begin(), candidates.end(), [](const CandidateFile& a, const CandidateFile& b) {
            if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
            auto ext_a = make_fspath(a.internal_name).extension();
            auto ext_b = make_fspath(b.internal_name).extension();
            if (ext_a != ext_b) return ext_a < ext_b;
            return a.internal_name < b.internal_name;
        });
    }

    // Synchronize (-as): remove archive entries not present in candidates
    if (cfg.sync_archive && updating_existing) {
        arch.entries.erase(
            std::remove_if(arch.entries.begin(), arch.entries.end(), [&](const RarFileEntry& e) {
                for (const auto& c : candidates) {
                    if (to_lower_ascii(c.internal_name) == to_lower_ascii(e.name)) return false;
                }
                out_println(cfg, "正在删除 " + to_native_slashes(e.name));
                return true;
            }),
            arch.entries.end());
    }

    Rar5Compressor compressor;
    compressor.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
    bool has_prior_solid_file = false;

    for (const auto& c : candidates) {
        // Check update (u) and freshen (f) semantics
        int existing_idx = -1;
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            if (to_lower_ascii(arch.entries[i].name) == to_lower_ascii(c.internal_name)) {
                existing_idx = (int)i;
                break;
            }
        }

        if (cfg.command == "f" && existing_idx < 0) {
            continue; // Freshen only updates files already in archive
        }
        if ((cfg.command == "u" || cfg.command == "f") && existing_idx >= 0) {
            if (c.mtime_winft <= arch.entries[existing_idx].mtime_winft) {
                continue; // Not newer
            }
        }

        std::vector<uint8_t> raw_data;
        if (!c.is_dir) {
            std::ifstream fin(c.disk_path, std::ios::binary);
            if (!fin) {
                err_println(cfg, "无法打开文件 " + fspath_to_utf8(c.disk_path));
                continue;
            }
            raw_data.assign((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        }

        // Check if extension is in -ms store list
        RarArchiveOptions entry_opts = cfg.arch_opts;
        if (!c.is_dir && !cfg.store_exts.empty()) {
            std::string ext = to_lower_ascii(fspath_to_utf8(c.disk_path.extension()));
            if (!ext.empty() && ext.front() == '.') ext.erase(ext.begin());
            for (const auto& se : cfg.store_exts) {
                if (ext == se) {
                    entry_opts.method = 0;
                    break;
                }
            }
        }

        // Handle -ver[n] file versioning
        if (cfg.version_control && existing_idx >= 0 && !c.is_dir) {
            uint64_t max_ver = 0;
            for (const auto& e : arch.entries) {
                if (to_lower_ascii(e.name) == to_lower_ascii(c.internal_name) && e.has_version) {
                    max_ver = std::max(max_ver, e.version_num);
                }
            }
            arch.entries[existing_idx].has_version = true;
            arch.entries[existing_idx].version_num = max_ver + 1;
            // Temporarily rename old entry so add_entry_from_memory appends new head entry
            std::string orig_name = arch.entries[existing_idx].name;
            arch.entries[existing_idx].name = orig_name + "\x01ver";
            arch.add_entry_from_memory(c.internal_name, raw_data.data(), raw_data.size(),
                                       c.is_dir, c.attrs, c.mtime_winft, c.ctime_winft, c.atime_winft,
                                       entry_opts, compressor,
                                       entry_opts.solid && has_prior_solid_file && !c.is_dir);
            arch.entries[existing_idx].name = orig_name;
        } else {
            arch.add_entry_from_memory(c.internal_name, raw_data.data(), raw_data.size(),
                                       c.is_dir, c.attrs, c.mtime_winft, c.ctime_winft, c.atime_winft,
                                       entry_opts, compressor,
                                       entry_opts.solid && has_prior_solid_file && !c.is_dir);
        }

        if (!c.is_dir && entry_opts.method > 0 && entry_opts.solid) {
            has_prior_solid_file = true;
        }

        if (!cfg.quiet_names) {
            std::string action = (existing_idx >= 0) ? "正在更新    " : "正在添加    ";
            out_println(cfg, action + to_native_slashes(c.internal_name) + "                                                    完成");
        }

        if (cfg.delete_after) {
            paths_to_delete_after.push_back(c.disk_path);
        }
#ifdef _WIN32
        if (cfg.clear_archive_attr && !c.is_dir) {
            DWORD cur_a = GetFileAttributesW(c.disk_path.c_str());
            if (cur_a != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesW(c.disk_path.c_str(), cur_a & ~FILE_ATTRIBUTE_ARCHIVE);
            }
        }
#endif
    }

    if (cfg.arch_opts.recovery_percent > 0) {
        out_println(cfg, "正在添加数据恢复记录");
    }
    if (cfg.arch_opts.lock_archive) {
        out_println(cfg, "正在锁定压缩文件");
    }

    std::vector<std::string> volumes;
    std::string save_err;
    RarExitCode src = arch.save(arch_path, cfg.arch_opts, &volumes, &save_err);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, "保存错误: " + save_err);
        return (int)src;
    }

    // Set archive timestamp to latest file if -tl
    if (cfg.latest_archive_time && !arch.entries.empty()) {
        uint64_t max_ft = 0;
        for (const auto& e : arch.entries) max_ft = std::max(max_ft, e.mtime_winft);
        if (max_ft > 0) {
            RarFileEntry dummy{};
            dummy.mtime_winft = max_ft;
            for (const auto& vp : volumes) {
                apply_extracted_times_and_attrs(make_fspath(vp), dummy, cfg);
            }
        }
    }

    // Test after archiving if -t
    if (cfg.test_after_archive && !volumes.empty()) {
        CliConfig tcfg = cfg;
        tcfg.command = "t";
        tcfg.archive_path = volumes.front();
        tcfg.file_args.clear();
        tcfg.quiet_copyright = true;
        int trc = cmd_test(tcfg);
        if (trc != RAR_EXIT_SUCCESS) return trc;
    }

    // Delete source files after successful archiving if -df / m / mf
    if (cfg.delete_after) {
        // Delete files first, then directories in reverse depth order
        std::sort(paths_to_delete_after.begin(), paths_to_delete_after.end(),
                  [](const fs::path& a, const fs::path& b) {
                      return a.wstring().size() > b.wstring().size();
                  });
        for (const auto& dp : paths_to_delete_after) {
            std::error_code ec;
            if (fs::is_directory(dp, ec) && cfg.move_files_only) continue;
            fs::remove(dp, ec);
        }
    }

    if (!cfg.quiet_done) out_println(cfg, "完成");
    return RAR_EXIT_SUCCESS;
}

int cmd_delete(const CliConfig& cfg) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)rc;
    }
    if (arch.is_locked) {
        err_println(cfg, "错误: 压缩文件已锁定");
        return RAR_EXIT_LOCKED;
    }

    out_println(cfg, "正在更新压缩文件 " + to_native_slashes(arch_path));
    out_println(cfg, "");

    size_t orig_count = arch.entries.size();
    std::vector<RarFileEntry> remaining;
    for (const auto& e : arch.entries) {
        if (matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) {
            out_println(cfg, "正在删除 " + to_native_slashes(e.name));
        } else {
            remaining.push_back(e);
        }
    }

    if (remaining.size() == orig_count) {
        out_println(cfg, "没有文件可删除");
        return RAR_EXIT_NO_FILES;
    }

    if (remaining.empty()) {
        std::error_code ec;
        fs::remove(make_fspath(arch_path), ec);
        out_println(cfg, "删除空的压缩文件 " + to_native_slashes(arch_path));
        if (!cfg.quiet_done) out_println(cfg, "完成");
        return RAR_EXIT_SUCCESS;
    }

    // If archive was solid, re-compress remaining entries so solid dictionary chain remains valid
    if (arch.is_solid) {
        RarArchive rebuilt = arch;
        rebuilt.entries.clear();
        Rar5Decompressor decomp;
        Rar5Compressor comp;
        comp.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
        bool has_solid = false;
        RarArchiveOptions ropts = cfg.arch_opts;
        ropts.solid = true;
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            const auto& e = arch.entries[i];
            std::vector<uint8_t> raw;
            arch.extract_entry(i, cfg.arch_opts.password, decomp, raw, nullptr);
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) {
                rebuilt.add_entry_from_memory(e.name, raw.data(), raw.size(), e.is_dir,
                                              e.attributes, e.mtime_winft, e.ctime_winft, e.atime_winft,
                                              ropts, comp, has_solid && !e.is_dir);
                if (!e.is_dir) has_solid = true;
            }
        }
        arch = std::move(rebuilt);
    } else {
        arch.entries = std::move(remaining);
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    sopts.lock_archive = arch.is_locked || cfg.arch_opts.lock_archive;
    RarExitCode src = arch.save(arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, "完成");
    return RAR_EXIT_SUCCESS;
}

int cmd_rename(const CliConfig& cfg) {
    print_banner(cfg);
    if (cfg.file_args.size() < 2 || (cfg.file_args.size() % 2) != 0) {
        err_println(cfg, "错误: rn 命令需要成对的 <源文件名> <目标文件名> 参数");
        return RAR_EXIT_USER_ERROR;
    }
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)rc;
    }
    if (arch.is_locked) {
        err_println(cfg, "错误: 压缩文件已锁定");
        return RAR_EXIT_LOCKED;
    }

    out_println(cfg, "正在更新压缩文件 " + to_native_slashes(arch_path));
    out_println(cfg, "");

    size_t renamed = 0;
    for (size_t p = 0; p + 1 < cfg.file_args.size(); p += 2) {
        std::string src_pat = normalize_internal_slashes(cfg.file_args[p]);
        std::string dst_pat = normalize_internal_slashes(cfg.file_args[p + 1]);
        for (auto& e : arch.entries) {
            if (wildcard_match(src_pat, e.name)) {
                std::string old_name = e.name;
                std::string new_name = dst_pat;
                if (dst_pat.find('*') != std::string::npos) {
                    // Simple wildcard extension replacement (e.g. *.txt -> *.bak)
                    fs::path ep = make_fspath(old_name);
                    if (dst_pat.substr(0, 2) == "*.") {
                        new_name = normalize_internal_slashes(
                            fspath_to_utf8(ep.parent_path() / ep.stem()) + dst_pat.substr(1));
                    }
                }
                out_println(cfg, "正在将 " + to_native_slashes(old_name) + " 重命名为 " + to_native_slashes(new_name));
                e.name = new_name;
                ++renamed;
            }
        }
    }

    if (renamed == 0) {
        out_println(cfg, "没有文件匹配");
        return RAR_EXIT_NO_FILES;
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    RarExitCode src = arch.save(arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, "完成");
    return RAR_EXIT_SUCCESS;
}

int cmd_comment_or_modify(const CliConfig& cfg, const std::string& self_exe_path) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }

    if (cfg.command == "r" || cfg.command == "rc") {
        // Repair archive
        fs::path ap = make_fspath(arch_path);
        fs::path fixed_path = ap.parent_path() / make_fspath("fixed." + fspath_to_utf8(ap.filename()));
        out_println(cfg, "正在修复压缩文件 " + to_native_slashes(arch_path));
        out_println(cfg, "正在重建 " + fspath_to_utf8(fixed_path));
        std::vector<std::string> found_names;
        bool used_rr = false;
        RarExitCode rrc = RarArchive::repair_archive(arch_path, fspath_to_utf8(fixed_path),
                                                     cfg.arch_opts.password, found_names, used_rr);
        if (used_rr) {
            out_println(cfg, "发现数据恢复记录");
        }
        for (const auto& fn : found_names) {
            out_println(cfg, "发现 " + to_native_slashes(fn));
        }
        if (rrc == RAR_EXIT_SUCCESS) {
            out_println(cfg, "已完成");
        } else {
            err_println(cfg, "修复失败: 未找到有效的 RAR 5.0 文件记录");
        }
        return (int)rrc;
    }

    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)rc;
    }

    if (cfg.command == "cw") {
        if (cfg.file_args.empty()) {
            err_println(cfg, "错误: cw 命令需要指定输出注释文件名");
            return RAR_EXIT_USER_ERROR;
        }
        std::string out_cfile = cfg.file_args[0];
        if (fs::exists(make_fspath(out_cfile)) && cfg.overwrite_mode == -1) {
            return RAR_EXIT_SUCCESS;
        }
        std::ofstream cf(make_fspath(out_cfile), std::ios::binary | std::ios::trunc);
        if (!cf) {
            err_println(cfg, "无法创建注释文件 " + out_cfile);
            return RAR_EXIT_CREATE_ERROR;
        }
        cf.write(arch.comment.data(), (std::streamsize)arch.comment.size());
        cf.close();
        out_println(cfg, "正在将注释写入 " + out_cfile + "                                                完成");
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.command == "i") {
        // Search string inside archive files
        Rar5Decompressor decomp;
        bool case_sens = (cfg.find_params.find('c') != std::string::npos);
        std::string needle = case_sens ? cfg.find_str : to_lower_ascii(cfg.find_str);
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            const auto& e = arch.entries[i];
            if (e.is_dir) continue;
            std::vector<uint8_t> data;
            if (arch.extract_entry(i, cfg.arch_opts.password, decomp, data, nullptr) == RAR_EXIT_SUCCESS) {
                std::string haystack(reinterpret_cast<const char*>(data.data()), data.size());
                std::string search_in = case_sens ? haystack : to_lower_ascii(haystack);
                size_t pos = search_in.find(needle);
                if (pos != std::string::npos) {
                    out_println(cfg, "");
                    out_println(cfg, "正在处理 " + to_native_slashes(arch_path));
                    out_println(cfg, "在 " + to_native_slashes(e.name) + " 中找到匹配:");
                    // Print matching line
                    size_t ls = haystack.rfind('\n', pos);
                    ls = (ls == std::string::npos) ? 0 : (ls + 1);
                    size_t le = haystack.find('\n', pos);
                    if (le != std::string::npos && le > ls && haystack[le - 1] == '\r') --le;
                    out_println(cfg, haystack.substr(ls, le - ls));
                }
            }
        }
        return RAR_EXIT_SUCCESS;
    }

    if (arch.is_locked) {
        err_println(cfg, "错误: 压缩文件已锁定");
        return RAR_EXIT_LOCKED;
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    sopts.lock_archive = arch.is_locked || cfg.arch_opts.lock_archive || (cfg.command == "k");
    if (arch.has_recovery && sopts.recovery_percent == 0) sopts.recovery_percent = 3;

    if (cfg.command == "c" || !cfg.comment_file.empty()) {
        if (!cfg.comment_file.empty()) {
            out_println(cfg, "正在从 " + cfg.comment_file + " 读取注释");
            std::ifstream cf(make_fspath(cfg.comment_file), std::ios::binary);
            if (cf) {
                arch.comment.assign((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
            }
        } else {
            out_println(cfg, "请输入注释 (以 Ctrl+Z 或 EOF 结束):");
            std::ostringstream ss;
            ss << std::cin.rdbuf();
            arch.comment = ss.str();
        }
        out_println(cfg, "正在添加注释到 " + to_native_slashes(arch_path) + "                                    完成");
    }

    if (cfg.command == "k") {
        out_println(cfg, "正在锁定压缩文件 " + to_native_slashes(arch_path));
        sopts.lock_archive = true;
    }

    if (cfg.command == "rr" || cfg.command == "rv") {
        out_println(cfg, "正在添加数据恢复记录到 " + to_native_slashes(arch_path));
    }

    if (cfg.command == "s") {
        std::string stub_src = cfg.sfx_stub_name.empty() ? self_exe_path : cfg.sfx_stub_name;
        arch.sfx_stub = RarArchive::create_default_sfx_stub(stub_src);
        fs::path ap = make_fspath(arch_path);
        ap.replace_extension(".exe");
        arch_path = fspath_to_utf8(ap);
        out_println(cfg, "正在创建自解压压缩文件 " + to_native_slashes(arch_path));
    } else if (cfg.command == "s-") {
        arch.sfx_stub.clear();
        fs::path ap = make_fspath(arch_path);
        ap.replace_extension(".rar");
        arch_path = fspath_to_utf8(ap);
        out_println(cfg, "正在创建压缩文件 " + to_native_slashes(arch_path));
    }

    RarExitCode src = arch.save(arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, "错误: " + err_msg);
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, "完成");
    return RAR_EXIT_SUCCESS;
}

// Check if the running executable itself has a RAR 5.0 archive appended (SFX execution mode)
bool is_self_sfx_archive(const std::string& exe_path) {
    if (exe_path.empty()) return false;
    RarArchive test_arch;
    return test_arch.load(exe_path) == RAR_EXIT_SUCCESS && !test_arch.sfx_stub.empty();
}

} // anonymous namespace

int CliRunner::run(int argc, const std::vector<std::string>& args) {
    CliConfig cfg;
    std::string self_exe_path = (!args.empty()) ? args[0] : "";

    // Check if binary name starts with "unrar" (unrar-free mode defaults)
    std::string exe_name = to_lower_ascii(fspath_to_utf8(make_fspath(self_exe_path).filename()));
    bool is_unrar_persona = (exe_name.find("unrar") != std::string::npos);

    bool stop_switches = false;
    std::vector<std::string> positional;

    for (size_t i = 1; i < (size_t)argc && i < args.size(); ++i) {
        const std::string& tok = args[i];
        if (!stop_switches && !tok.empty() && tok[0] == '-') {
            if (!parse_switch(tok, cfg, args, i)) {
                stop_switches = true;
            }
            continue;
        }
        if (cfg.command.empty() && positional.empty() && is_known_command(tok, cfg)) {
            continue;
        }
        positional.push_back(tok);
    }

    if (cfg.show_version) {
        out_println(cfg, "7.01");
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.show_help) {
        print_help(cfg);
        return RAR_EXIT_SUCCESS;
    }

    // If invoked without command on an SFX executable, automatically extract self!
    if (cfg.command.empty() && is_self_sfx_archive(self_exe_path)) {
        cfg.command = "x";
        if (!positional.empty()) {
            cfg.dest_dir = positional[0];
        }
        return cmd_extract_or_print(cfg, self_exe_path);
    }

    // In unrar-free persona, if no command was specified but an archive was given, default to "x"
    if (cfg.command.empty() && is_unrar_persona && !positional.empty()) {
        cfg.command = "x";
    }

    if (cfg.command.empty()) {
        print_help(cfg);
        return RAR_EXIT_SUCCESS;
    }

    // Handle special `rar i[par]=<str> <archive>` case where archive is first positional
    if (positional.empty()) {
        err_println(cfg, "错误: 未指定压缩文件名");
        return RAR_EXIT_USER_ERROR;
    }

    cfg.archive_path = positional[0];
    for (size_t i = 1; i < positional.size(); ++i) {
        cfg.file_args.push_back(positional[i]);
    }

    // For extraction commands (x, e), check if the last positional argument is a destination directory
    if ((cfg.command == "x" || cfg.command == "e") && !cfg.file_args.empty()) {
        const std::string& last_arg = cfg.file_args.back();
        bool ends_with_slash = (!last_arg.empty() && (last_arg.back() == '\\' || last_arg.back() == '/'));
        std::error_code ec;
        bool exists_as_dir = fs::is_directory(make_fspath(last_arg), ec);
        if (ends_with_slash || exists_as_dir) {
            cfg.dest_dir = last_arg;
            cfg.file_args.pop_back();
        }
    }

    if (cfg.command == "l" || cfg.command == "lt" || cfg.command == "lta" || cfg.command == "lb" ||
        cfg.command == "v" || cfg.command == "vt" || cfg.command == "vta" || cfg.command == "vb") {
        return cmd_list(cfg);
    }
    if (cfg.command == "t") {
        return cmd_test(cfg);
    }
    if (cfg.command == "x" || cfg.command == "e" || cfg.command == "p") {
        return cmd_extract_or_print(cfg);
    }
    if (cfg.command == "a" || cfg.command == "u" || cfg.command == "f" ||
        cfg.command == "m" || cfg.command == "mf") {
        return cmd_add_or_update(cfg, self_exe_path);
    }
    if (cfg.command == "d") {
        return cmd_delete(cfg);
    }
    if (cfg.command == "rn") {
        return cmd_rename(cfg);
    }
    if (cfg.command == "c" || cfg.command == "cw" || cfg.command == "k" ||
        cfg.command == "rr" || cfg.command == "rv" || cfg.command == "s" ||
        cfg.command == "s-" || cfg.command == "r" || cfg.command == "rc" ||
        cfg.command == "ch" || cfg.command == "i") {
        return cmd_comment_or_modify(cfg, self_exe_path);
    }

    err_println(cfg, "未知命令: " + cfg.command);
    return RAR_EXIT_USER_ERROR;
}

} // namespace openrar
