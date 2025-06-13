#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <cwctype>
#include <filesystem>

// RAII handle closer
struct HandleCloser {
    void operator()(HANDLE h) const {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

// RAII privilege manager
class PrivilegeGuard {
public:
    explicit PrivilegeGuard(const wchar_t* privilege)
        : privilege_(privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_)) {
            throw std::runtime_error("Failed to open process token: " + std::to_string(GetLastError()));
        }
        if (!LookupPrivilegeValueW(nullptr, privilege_, &luid_)) {
            throw std::runtime_error("Failed to lookup privilege value: " + std::to_string(GetLastError()));
        }
    }
    void enable() {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid_;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token_, FALSE, &tp, 0, nullptr, nullptr)) {

            DWORD error = GetLastError();
            std::wstring priv_name(privilege_);
            std::string narrow_priv;

            narrow_priv.resize(
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    priv_name.c_str(),
                    -1,
                    nullptr,
                    0,
                    nullptr,
                    nullptr));
            WideCharToMultiByte(
                CP_UTF8,
                0,
                priv_name.c_str(),
                -1,
                narrow_priv.data(),
                narrow_priv.size(),
                nullptr,
                nullptr);
            throw std::runtime_error("Failed to enable " + narrow_priv + ": Error " + std::to_string(error) + ". Please run this program as an administrator (right-click and select 'Run as administrator' or use an elevated Command Prompt).");
        }
        enabled_ = true;
    }
    ~PrivilegeGuard() {
        if (enabled_) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid_;
            tp.Privileges[0].Attributes = 0;
            AdjustTokenPrivileges(token_, FALSE, &tp, 0, nullptr, nullptr);
        }
        if (token_ != INVALID_HANDLE_VALUE) CloseHandle(token_);
    }
private:
    const wchar_t* privilege_  = nullptr;
    HANDLE token_ = INVALID_HANDLE_VALUE;
    LUID luid_{};
    bool enabled_ = false;
};

// Check if the process is running with elevated privileges
static bool IsProcessElevated() {
    bool is_elevated = false;
    HANDLE token = INVALID_HANDLE_VALUE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            is_elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    return is_elevated;
}

// Check if filename is a valid 8.3 name
static bool is_valid_83_name(const std::wstring& filename) {
    std::filesystem::path p(filename);
    const auto& stem = p.stem().wstring();
    auto ext(p.extension().wstring());
    if (!ext.empty() && ext[0] == L'.') {
        ext = ext.substr(1);
    }
    return stem.length() <= 8 && ext.length() <= 3;
}

// Get short path using GetShortPathNameW
static std::wstring get_short_path(const std::wstring& path) {
    DWORD length = GetShortPathNameW(path.c_str(), nullptr, 0);
    if (length == 0) {
        throw std::runtime_error("Failed to GetShortPathNameW length: " + std::to_string(GetLastError()));
    }
    std::wstring short_path(length - 1, L'\0');
    if (!GetShortPathNameW(path.c_str(), short_path.data(), length)) {
        throw std::runtime_error("GetShortPathNameW failed: " + std::to_string(GetLastError()));
    }
    short_path.resize(wcslen(short_path.c_str()));
    return short_path;
}

// Clean string: uppercase alphanumeric and '_'
static std::wstring clean_name(const std::wstring& name) {
    std::wstring cleaned;
    for (wchar_t c : name) {
        if (std::iswalnum(c) || c == L'_') {
            cleaned += std::towupper(c);
        }
    }
    return cleaned;
}

// Generate short name candidate
static std::wstring generate_short_name(const std::filesystem::path& path, int counter) {
    const auto& stem = path.stem().wstring();
    auto ext(path.extension().wstring());
    if (!ext.empty() && ext[0] == L'.') {
        ext = ext.substr(1);
    }

    auto clean_stem(clean_name(stem));
    const auto& clean_ext = clean_name(ext).substr(0, 3);
    if (clean_stem.empty()) {
        clean_stem = L"FILE";
    }

    const auto& suffix = L"~" + std::to_wstring(counter);
    auto stem_len = 8 - suffix.length();
    stem_len = std::min(stem_len, clean_stem.length());
    const auto& stem_base = clean_stem.substr(0, stem_len);

    return stem_base + suffix + (clean_ext.empty() ? L"" : L"." + clean_ext);
}

static std::wstring get_unc_path(const std::wstring& path) {
    std::wstring result;
    try {
        const auto& abs_path = std::filesystem::absolute(path);
        const auto& full_path = abs_path.wstring();
        result = full_path.substr(0, 2) == L"\\\\"
            ? (full_path.substr(2, 2) == L"?\\"
                ? full_path
                : L"\\\\?\\UNC" + full_path.substr(1))
            : L"\\\\?\\" + full_path;
    } catch (const std::filesystem::filesystem_error& e) {
        throw std::runtime_error("Failed to get absolute path: " + std::string(e.what()));
    }
    return result;
}

// Set short name if none exists
static void process_path(const std::wstring& input_path) {
    bool success = false;
    std::wstring error_message;

    try {
        std::wcout << L"processing '" << input_path << L"'\n";
        std::filesystem::path path(input_path);
        if (!std::filesystem::exists(path)) {
            error_message = L"Path does not exist: " + input_path;
        }
        else {
            const auto& unc_path = get_unc_path(input_path);
            const auto& short_path = get_short_path(unc_path);
            const auto& short_filename = std::filesystem::path(short_path).filename().wstring();

            if (is_valid_83_name(short_filename)) {
                std::wcout << L"Short name exists for " << input_path << L": " << short_filename << L"\n";
                success = true;
            }
            else {
                PrivilegeGuard guard(L"SeRestorePrivilege");
                guard.enable();

                std::wcout << L"unc '" << unc_path << L"'\n";
                UniqueHandle hFile(
                    CreateFileW(
                        unc_path.c_str(),
                        DELETE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                        nullptr),
                    HandleCloser());
                if (!hFile || hFile.get() == INVALID_HANDLE_VALUE) {
                    error_message = L"Failed to open file/directory: " + std::to_wstring(GetLastError());
                }
                else {
                    bool name_set = false;
                    for (int counter = 1; counter <= 100 && !name_set; ++counter) {
                        const auto& short_name = generate_short_name(path, counter);
                        if (SetFileShortNameW(hFile.get(), short_name.c_str())) {
                            std::wcout << L"Set short name for " << input_path << L" to " << short_name << L"\n";
                            success = true;
                            name_set = true;
                        }
                        else if (GetLastError() == ERROR_ALREADY_EXISTS) {
                            continue;
                        }
                        else {
                            error_message = L"Failed to set short name: " + std::to_wstring(GetLastError());
                            break;
                        }
                    }
                    if (!name_set) {
                        error_message = L"Too many attempts to set short name for " + input_path;
                    }
                }
            }
        }
    }
    catch (const std::exception& e) {
        error_message = L"Error processing " + input_path + L": " + std::wstring(e.what(), e.what() + strlen(e.what()));
    }

    if (!success && !error_message.empty()) {
        std::wcerr << error_message << L"\n";
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: FixShortName.exe <path1> <path2> ...\n";
        return 1;
    }

    // Check if running with elevated privileges
    if (!IsProcessElevated()) {
        std::wcerr << L"Error: This program requires administrative privileges. Please run it as an administrator (right-click and select 'Run as administrator' or use an elevated Command Prompt).\n";
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        process_path(argv[i]);
    }
    return 0;
}
