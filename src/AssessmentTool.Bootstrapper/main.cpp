#include "BootstrapDecision.h"

#if __has_include("GeneratedHashes.h")
#include "GeneratedHashes.h"
#else
#include "GeneratedHashes.example.h"
#endif

#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <winternl.h>

#include <array>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

using AssessmentTool::Bootstrapper::BootstrapAction;
using AssessmentTool::Bootstrapper::BootstrapDecisionInput;
using AssessmentTool::Bootstrapper::DecideBootstrapAction;

namespace
{
    constexpr wchar_t ApplicationFileName[] = L"AssessmentTool.App.exe";
    constexpr wchar_t ManifestFileName[] = L"SHA256SUMS.txt";
    constexpr wchar_t DotNetDownloadUrl[] = L"https://dotnet.microsoft.com/download/dotnet-framework/net48";
    constexpr DWORD DotNet48Release = 528040;

    bool IsDiagnosticMode(const wchar_t* commandLine)
    {
        return commandLine != nullptr
            && wcscmp(commandLine, L"--diagnose-exit-code") == 0;
    }

    int ToDiagnosticExitCode(BootstrapAction action)
    {
        switch (action)
        {
        case BootstrapAction::ShowUnsupportedWindows:
            return 10;
        case BootstrapAction::ShowDotNetRemediation:
            return 11;
        case BootstrapAction::ShowRepairFiles:
            return 12;
        case BootstrapAction::LaunchApplication:
            return 0;
        default:
            return 14;
        }
    }

    std::wstring GetExecutableDirectory()
    {
        std::vector<wchar_t> buffer(32768);
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= static_cast<DWORD>(buffer.size()))
        {
            return {};
        }

        std::wstring path(buffer.data(), length);
        const std::wstring::size_type separator = path.find_last_of(L"\\/");
        return separator == std::wstring::npos ? std::wstring{} : path.substr(0, separator);
    }

    std::wstring CombinePath(const std::wstring& directory, const wchar_t* fileName)
    {
        if (directory.empty())
        {
            return {};
        }

        return directory + L"\\" + fileName;
    }

    bool IsRegularFile(const std::wstring& path)
    {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES
            && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
            && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    }

    HANDLE OpenRegularFileForVerification(const std::wstring& path)
    {
        HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return INVALID_HANDLE_VALUE;
        }

        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!GetFileInformationByHandleEx(
                file,
                FileAttributeTagInfo,
                &attributes,
                sizeof(attributes))
            || (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            CloseHandle(file);
            return INVALID_HANDLE_VALUE;
        }

        return file;
    }

    bool IsSupportedWindows()
    {
        using RtlGetVersionFunction = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
        const HMODULE module = GetModuleHandleW(L"ntdll.dll");
        if (module == nullptr)
        {
            return false;
        }

        #pragma warning(suppress: 4191)
        const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
            GetProcAddress(module, "RtlGetVersion"));
        if (rtlGetVersion == nullptr)
        {
            return false;
        }

        RTL_OSVERSIONINFOW version{};
        version.dwOSVersionInfoSize = static_cast<DWORD>(sizeof(version));
        return rtlGetVersion(&version) == 0 && version.dwMajorVersion >= 10;
    }

    bool HasDotNet48()
    {
        HKEY key = nullptr;
        const LSTATUS openResult = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
            0,
            KEY_READ | KEY_WOW64_32KEY,
            &key);
        if (openResult != ERROR_SUCCESS)
        {
            return false;
        }

        DWORD release = 0;
        DWORD size = sizeof(release);
        DWORD type = 0;
        const LSTATUS queryResult = RegQueryValueExW(
            key,
            L"Release",
            nullptr,
            &type,
            reinterpret_cast<BYTE*>(&release),
            &size);
        RegCloseKey(key);
        return queryResult == ERROR_SUCCESS
            && type == REG_DWORD
            && size == sizeof(release)
            && release >= DotNet48Release;
    }

    std::wstring ComputeSha256(HANDLE file)
    {
        if (file == INVALID_HANDLE_VALUE)
        {
            return {};
        }

        LARGE_INTEGER beginning{};
        if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN))
        {
            return {};
        }

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        std::vector<UCHAR> hashObject;
        std::array<UCHAR, 32> digest{};
        std::wstring result;
        DWORD objectLength = 0;
        DWORD copied = 0;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0
            && BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectLength),
                sizeof(objectLength),
                &copied,
                0) >= 0)
        {
            hashObject.resize(objectLength);
            if (BCryptCreateHash(
                    algorithm,
                    &hash,
                    hashObject.data(),
                    static_cast<ULONG>(hashObject.size()),
                    nullptr,
                    0,
                    0) >= 0)
            {
                std::array<UCHAR, 65536> buffer{};
                DWORD bytesRead = 0;
                bool valid = true;
                while (true)
                {
                    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
                    {
                        valid = false;
                        break;
                    }
                    if (bytesRead == 0)
                    {
                        break;
                    }
                    if (BCryptHashData(hash, buffer.data(), bytesRead, 0) < 0)
                    {
                        valid = false;
                        break;
                    }
                }

                if (valid
                    && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0)
                {
                    constexpr wchar_t Hex[] = L"0123456789abcdef";
                    result.reserve(digest.size() * 2);
                    for (const UCHAR value : digest)
                    {
                        result.push_back(Hex[value >> 4]);
                        result.push_back(Hex[value & 0x0f]);
                    }
                }
            }
        }

        if (hash != nullptr)
        {
            BCryptDestroyHash(hash);
        }
        if (algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return result;
    }

    bool EqualHash(const std::wstring& actual, const wchar_t* expected)
    {
        if (actual.size() != 64 || expected == nullptr || wcslen(expected) != 64)
        {
            return false;
        }

        for (std::wstring::size_type index = 0; index < actual.size(); ++index)
        {
            if (std::towlower(actual[index]) != std::towlower(expected[index]))
            {
                return false;
            }
        }
        return true;
    }

    int ShowUnsupportedWindows()
    {
        MessageBoxW(
            nullptr,
            L"本软件仅支持 Windows 10 和 Windows 11 x64。当前系统未通过启动检查，软件不会继续运行。",
            L"系统版本不受支持",
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return 10;
    }

    int ShowDotNetRemediation()
    {
        const int choice = MessageBoxW(
            nullptr,
            L"本软件需要 Microsoft .NET Framework 4.8。当前电脑未检测到该组件。\n\n"
            L"是否打开微软官方下载页面？下载和安装前请核对来源；安装可能需要管理员权限和重启电脑。\n\n"
            L"选择“否”可退出，稍后使用可信离线安装包处理。",
            L"缺少运行环境",
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND);
        if (choice == IDYES)
        {
            ShellExecuteW(nullptr, L"open", DotNetDownloadUrl, nullptr, nullptr, SW_SHOWNORMAL);
        }
        return 11;
    }

    int ShowRepairFiles()
    {
        MessageBoxW(
            nullptr,
            L"软件包不完整或主程序完整性校验失败。为保护项目资料，启动检查器没有运行主程序。\n\n"
            L"请重新下载成功的 GitHub Actions 体验包并完整解压，不要单独复制或替换 EXE、DLL 和清单文件。",
            L"软件包需要修复",
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return 12;
    }

    int LaunchApplication(const std::wstring& applicationPath, const std::wstring& workingDirectory)
    {
        std::wstring commandLine = L"\"" + applicationPath + L"\"";
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        if (!CreateProcessW(
                applicationPath.c_str(),
                commandLine.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                workingDirectory.c_str(),
                &startupInfo,
                &processInfo))
        {
            MessageBoxW(
                nullptr,
                L"主程序通过完整性检查，但 Windows 无法启动它。请检查安全软件拦截记录，或重新解压完整体验包。",
                L"启动失败",
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            return 13;
        }

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return 0;
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR commandLine, int)
{
    const std::wstring directory = GetExecutableDirectory();
    const std::wstring applicationPath = CombinePath(directory, ApplicationFileName);
    const std::wstring manifestPath = CombinePath(directory, ManifestFileName);
    HANDLE applicationHandle = OpenRegularFileForVerification(applicationPath);
    const bool hasApplication = applicationHandle != INVALID_HANDLE_VALUE;
    const BootstrapDecisionInput input{
        IsSupportedWindows(),
        HasDotNet48(),
        hasApplication,
        IsRegularFile(manifestPath),
        hasApplication && EqualHash(ComputeSha256(applicationHandle), ASSESSMENTTOOL_APP_SHA256)
    };

    const BootstrapAction action = DecideBootstrapAction(input);
    if (IsDiagnosticMode(commandLine))
    {
        if (applicationHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(applicationHandle);
        }
        return ToDiagnosticExitCode(action);
    }

    int exitCode = 14;
    switch (action)
    {
    case BootstrapAction::ShowUnsupportedWindows:
        exitCode = ShowUnsupportedWindows();
        break;
    case BootstrapAction::ShowDotNetRemediation:
        exitCode = ShowDotNetRemediation();
        break;
    case BootstrapAction::ShowRepairFiles:
        exitCode = ShowRepairFiles();
        break;
    case BootstrapAction::LaunchApplication:
        exitCode = LaunchApplication(applicationPath, directory);
        break;
    default:
        break;
    }

    if (applicationHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(applicationHandle);
    }
    return exitCode;
}
