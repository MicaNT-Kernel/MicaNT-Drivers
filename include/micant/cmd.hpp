#pragma once

/**
 * @file cmd.hpp
 * @brief MicaNT Windows Command Prompt (cmd.exe) & Batch Scripting Engine.
 *
 * Provides a clean-room implementation of the Windows Command Processor:
 * - Full built-in command parity (COPY, XCOPY, DEL, MD, RD, REN, MOVE, ATTRIB, TREE,
 *   TYPE, FIND, FINDSTR, MORE, SORT, WHERE, SET, SETLOCAL, ENDLOCAL, TITLE, COLOR,
 *   PATH, PROMPT, VOL, LABEL, DATE, TIME, ECHO, IF, FOR, GOTO, CALL, SHIFT, PAUSE,
 *   REM, TIMEOUT, CHOICE, TASKLIST, TASKKILL, START, ASSOC, FTYPE, EXIT).
 * - Compound and pipeline operators (&, &&, ||, |, >, >>, <, 2>, 2>&1).
 * - SET /A arithmetic expression evaluator with precedence, bitwise & assignments.
 * - Dynamic pseudo-variables (%ERRORLEVEL%, %CD%, %DATE%, %TIME%, %RANDOM%, %CMDEXTVERSION%).
 * - Full Batch script (.bat/.cmd) interpreter with %0..%9, %*, %~dp0, %~nx0, %~f0, %~1,
 *   subroutine calls (CALL :label), label jumping (GOTO :label, GOTO :EOF), and local variable scopes.
 * - CLI switches: cmd /c <cmd>, cmd /k <cmd>, cmd /q, cmd /v:on, cmd /v:off.
 */

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <map>
#include <stack>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <iomanip>
#include <chrono>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "fs.hpp"
#include "conhost.hpp"
#include "user32.hpp"
#include "csrss.hpp"
#include "ldr.hpp"

namespace micant::cmd {

// ============================================================================
// 1. String Utilities & Case-Insensitive Helpers
// ============================================================================

inline std::string toUpper(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) res.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    return res;
}

inline std::string toLower(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return res;
}

inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

inline std::string trim(std::string_view s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

inline std::string stripQuotes(std::string_view s) {
    std::string t = trim(s);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') {
        return t.substr(1, t.size() - 2);
    }
    return t;
}

inline bool wildcardMatch(std::string_view pattern, std::string_view str) {
    size_t p = 0, s = 0;
    size_t starP = std::string_view::npos, matchS = 0;
    while (s < str.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || std::tolower(static_cast<unsigned char>(pattern[p])) == std::tolower(static_cast<unsigned char>(str[s])))) {
            p++;
            s++;
        } else if (p < pattern.size() && pattern[p] == '*') {
            starP = p++;
            matchS = s;
        } else if (starP != std::string_view::npos) {
            p = starP + 1;
            s = ++matchS;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') p++;
    return p == pattern.size();
}

// ============================================================================
// 2. Environment & Variable Scoping (CmdEnvironment)
// ============================================================================

class CmdEnvironment {
public:
    struct ScopeFrame {
        std::unordered_map<std::string, std::string> vars;
        bool delayedExpansion{false};
        bool extensionsEnabled{true};
    };

    CmdEnvironment() {
        resetDefaults();
    }

    void resetDefaults() {
        m_scopes.clear();
        m_globalVars.clear();
        m_delayedExpansion = false;
        m_extensionsEnabled = true;

        m_globalVars["OS"] = "MicaNT";
        m_globalVars["SystemRoot"] = "C:\\Windows";
        m_globalVars["windir"] = "C:\\Windows";
        m_globalVars["ComSpec"] = "C:\\Windows\\System32\\cmd.exe";
        m_globalVars["PATH"] = "C:\\Windows\\System32;C:\\Windows;C:\\bin";
        m_globalVars["PATHEXT"] = ".COM;.EXE;.BAT;.CMD;.VBS;.JS";
        m_globalVars["NUMBER_OF_PROCESSORS"] = "4";
        m_globalVars["PROCESSOR_ARCHITECTURE"] = "AMD64";
        m_globalVars["USERPROFILE"] = "C:\\Users\\admin";
        m_globalVars["HOMEDRIVE"] = "C:";
        m_globalVars["HOMEPATH"] = "\\Users\\admin";
        m_globalVars["PROMPT"] = "$P$G";
        m_globalVars["CMDEXTVERSION"] = "2";
    }

    void setVar(std::string_view key, std::string_view value) {
        std::string upperKey = toUpper(key);
        if (value.empty()) {
            if (!m_scopes.empty()) {
                m_scopes.back().vars.erase(upperKey);
            }
            m_globalVars.erase(upperKey);
        } else {
            if (!m_scopes.empty()) {
                m_scopes.back().vars[upperKey] = std::string(value);
            } else {
                m_globalVars[upperKey] = std::string(value);
            }
        }
        // Mirror to win32 environment
        std::wstring wKey(key.begin(), key.end());
        std::wstring wVal(value.begin(), value.end());
        win32::SetEnvironmentVariableW(wKey.c_str(), value.empty() ? nullptr : wVal.c_str());
    }

    bool getVar(std::string_view key, std::string& outVal, int lastExitCode = 0) const {
        std::string upperKey = toUpper(key);

        // Dynamic Pseudo-Variables
        if (upperKey == "ERRORLEVEL") {
            outVal = std::to_string(lastExitCode);
            return true;
        }
        if (upperKey == "CD") {
            wchar_t cur[260]{};
            win32::GetCurrentDirectoryW(260, cur);
            outVal.clear();
            for (int i = 0; cur[i] != L'\0'; ++i) outVal.push_back(static_cast<char>(cur[i] & 0x7F));
            if (outVal.empty()) outVal = "C:\\";
            return true;
        }
        if (upperKey == "DATE") {
            win32::SYSTEMTIME st{};
            win32::GetLocalTime(&st);
            std::ostringstream ss;
            ss << std::setfill('0') << std::setw(2) << st.wMonth << "/"
               << std::setw(2) << st.wDay << "/" << st.wYear;
            outVal = ss.str();
            return true;
        }
        if (upperKey == "TIME") {
            win32::SYSTEMTIME st{};
            win32::GetLocalTime(&st);
            std::ostringstream ss;
            ss << std::setfill('0') << std::setw(2) << st.wHour << ":"
               << std::setw(2) << st.wMinute << ":"
               << std::setw(2) << st.wSecond << "."
               << std::setw(2) << (st.wMilliseconds / 10);
            outVal = ss.str();
            return true;
        }
        if (upperKey == "RANDOM") {
            outVal = std::to_string(std::rand() % 32768);
            return true;
        }
        if (upperKey == "CMDEXTVERSION") {
            outVal = "2";
            return true;
        }
        if (upperKey == "CMDCMDLINE") {
            outVal = "cmd.exe";
            return true;
        }

        // Search active scope stack top-down
        for (auto it = m_scopes.rbegin(); it != m_scopes.rend(); ++it) {
            auto fit = it->vars.find(upperKey);
            if (fit != it->vars.end()) {
                outVal = fit->second;
                return true;
            }
        }

        auto git = m_globalVars.find(upperKey);
        if (git != m_globalVars.end()) {
            outVal = git->second;
            return true;
        }

        // Try win32 environment
        std::wstring wKey(key.begin(), key.end());
        wchar_t buf[512]{};
        win32::DWORD len = win32::GetEnvironmentVariableW(wKey.c_str(), buf, 512);
        if (len > 0) {
            outVal.clear();
            for (win32::DWORD i = 0; i < len; ++i) outVal.push_back(static_cast<char>(buf[i] & 0x7F));
            return true;
        }

        return false;
    }

    bool isDefined(std::string_view key, int lastExitCode = 0) const {
        std::string dummy;
        return getVar(key, dummy, lastExitCode);
    }

    std::map<std::string, std::string> getAllVars() const {
        std::map<std::string, std::string> merged;
        for (const auto& [k, v] : m_globalVars) merged[k] = v;
        for (const auto& sc : m_scopes) {
            for (const auto& [k, v] : sc.vars) merged[k] = v;
        }
        return merged;
    }

    void pushScope(bool enableDelayed, bool enableExt) {
        ScopeFrame frame;
        frame.vars = getAllVarsHash();
        frame.delayedExpansion = enableDelayed;
        frame.extensionsEnabled = enableExt;
        m_scopes.push_back(std::move(frame));
        m_delayedExpansion = enableDelayed;
        m_extensionsEnabled = enableExt;
    }

    bool popScope() {
        if (m_scopes.empty()) return false;
        m_scopes.pop_back();
        if (!m_scopes.empty()) {
            m_delayedExpansion = m_scopes.back().delayedExpansion;
            m_extensionsEnabled = m_scopes.back().extensionsEnabled;
        } else {
            m_delayedExpansion = false;
            m_extensionsEnabled = true;
        }
        return true;
    }

    void setDelayedExpansion(bool enable) noexcept { m_delayedExpansion = enable; }
    [[nodiscard]] bool isDelayedExpansionEnabled() const noexcept { return m_delayedExpansion; }

    void setExtensionsEnabled(bool enable) noexcept { m_extensionsEnabled = enable; }
    [[nodiscard]] bool areExtensionsEnabled() const noexcept { return m_extensionsEnabled; }

    std::string expandVariables(std::string_view text, int lastExitCode = 0, bool expandDelayed = false) const {
        std::string out;
        out.reserve(text.size() * 2);

        for (size_t i = 0; i < text.size(); ++i) {
            char ch = text[i];
            // Normal %VAR% expansion
            if (ch == '%' && i + 1 < text.size()) {
                if (text[i + 1] == '%') {
                    // Escaped %% in batch file -> single %
                    out.push_back('%');
                    i++;
                    continue;
                }
                size_t close = text.find('%', i + 1);
                if (close != std::string_view::npos) {
                    std::string rawVar = std::string(text.substr(i + 1, close - i - 1));
                    if (!rawVar.empty() && rawVar.find_first_of(" \t\r\n") == std::string::npos) {
                        out += evaluateVarExpression(rawVar, lastExitCode);
                        i = close;
                        continue;
                    }
                }
            }
            // Delayed !VAR! expansion
            if (expandDelayed && m_delayedExpansion && ch == '!' && i + 1 < text.size()) {
                size_t close = text.find('!', i + 1);
                if (close != std::string_view::npos) {
                    std::string rawVar = std::string(text.substr(i + 1, close - i - 1));
                    if (!rawVar.empty() && rawVar.find_first_of(" \t\r\n") == std::string::npos) {
                        out += evaluateVarExpression(rawVar, lastExitCode);
                        i = close;
                        continue;
                    }
                }
            }
            out.push_back(ch);
        }
        return out;
    }

private:
    std::unordered_map<std::string, std::string> getAllVarsHash() const {
        std::unordered_map<std::string, std::string> res = m_globalVars;
        for (const auto& sc : m_scopes) {
            for (const auto& [k, v] : sc.vars) res[k] = v;
        }
        return res;
    }

    std::string evaluateVarExpression(const std::string& rawVar, int lastExitCode) const {
        // Syntax 1: VAR:~start,len or VAR:~start
        size_t tildePos = rawVar.find(":~");
        if (tildePos != std::string::npos) {
            std::string varName = rawVar.substr(0, tildePos);
            std::string sliceSpec = rawVar.substr(tildePos + 2);
            std::string val;
            if (!getVar(varName, val, lastExitCode)) return "";
            return sliceString(val, sliceSpec);
        }

        // Syntax 2: VAR:old=new
        size_t colonPos = rawVar.find(':');
        if (colonPos != std::string::npos) {
            std::string varName = rawVar.substr(0, colonPos);
            std::string subst = rawVar.substr(colonPos + 1);
            size_t eqPos = subst.find('=');
            if (eqPos != std::string::npos) {
                std::string oldPattern = subst.substr(0, eqPos);
                std::string newPattern = subst.substr(eqPos + 1);
                std::string val;
                if (!getVar(varName, val, lastExitCode)) return "";
                return replaceAll(val, oldPattern, newPattern);
            }
        }

        // Standard variable lookup
        std::string val;
        if (getVar(rawVar, val, lastExitCode)) {
            return val;
        }
        return "";
    }

    static std::string sliceString(std::string_view s, std::string_view spec) {
        int64_t start = 0;
        int64_t len = static_cast<int64_t>(s.size());
        size_t comma = spec.find(',');
        if (comma != std::string_view::npos) {
            start = std::strtoll(std::string(spec.substr(0, comma)).c_str(), nullptr, 10);
            len = std::strtoll(std::string(spec.substr(comma + 1)).c_str(), nullptr, 10);
        } else {
            start = std::strtoll(std::string(spec).c_str(), nullptr, 10);
        }

        int64_t sz = static_cast<int64_t>(s.size());
        if (start < 0) start = sz + start;
        if (start < 0) start = 0;
        if (start >= sz) return "";

        if (len < 0) len = (sz + len) - start;
        if (len <= 0) return "";
        if (start + len > sz) len = sz - start;

        return std::string(s.substr(static_cast<size_t>(start), static_cast<size_t>(len)));
    }

    static std::string replaceAll(std::string_view src, std::string_view oldSub, std::string_view newSub) {
        if (oldSub.empty()) return std::string(src);
        std::string res;
        size_t pos = 0;
        while (pos < src.size()) {
            size_t found = src.find(oldSub, pos);
            if (found == std::string_view::npos) {
                res.append(src.substr(pos));
                break;
            }
            res.append(src.substr(pos, found - pos));
            res.append(newSub);
            pos = found + oldSub.size();
        }
        return res;
    }

    std::unordered_map<std::string, std::string> m_globalVars;
    std::vector<ScopeFrame> m_scopes;
    bool m_delayedExpansion{false};
    bool m_extensionsEnabled{true};
};

// ============================================================================
// 3. SET /A Arithmetic Evaluator (SetArithmetic)
// ============================================================================

class SetArithmetic {
public:
    static int64_t evaluate(std::string_view expr, CmdEnvironment& env, int lastExitCode = 0) {
        std::string s = trim(expr);
        if (s.empty()) return 0;
        SetArithmetic parser(s, env, lastExitCode);
        return parser.parseCommaExpression();
    }

private:
    SetArithmetic(std::string_view str, CmdEnvironment& env, int lastExitCode)
        : m_str(str), m_env(env), m_lastExitCode(lastExitCode) {}

    void skipWhitespace() {
        while (m_pos < m_str.size() && (m_str[m_pos] == ' ' || m_str[m_pos] == '\t' || m_str[m_pos] == '\r' || m_str[m_pos] == '\n')) {
            m_pos++;
        }
    }

    int64_t parseCommaExpression() {
        int64_t res = parseAssignment();
        skipWhitespace();
        while (m_pos < m_str.size() && m_str[m_pos] == ',') {
            m_pos++;
            res = parseAssignment();
            skipWhitespace();
        }
        return res;
    }

    int64_t parseAssignment() {
        skipWhitespace();
        size_t savePos = m_pos;

        // Check if there's an identifier on the left
        std::string ident;
        if (parseIdentifier(ident)) {
            skipWhitespace();
            // Check for assignment operator
            if (match("="))   { int64_t val = parseAssignment(); assignVar(ident, val); return val; }
            if (match("+="))  { int64_t val = getVarVal(ident) + parseAssignment(); assignVar(ident, val); return val; }
            if (match("-="))  { int64_t val = getVarVal(ident) - parseAssignment(); assignVar(ident, val); return val; }
            if (match("*="))  { int64_t val = getVarVal(ident) * parseAssignment(); assignVar(ident, val); return val; }
            if (match("/="))  { int64_t rhs = parseAssignment(); int64_t val = rhs != 0 ? getVarVal(ident) / rhs : 0; assignVar(ident, val); return val; }
            if (match("%="))  { int64_t rhs = parseAssignment(); int64_t val = rhs != 0 ? getVarVal(ident) % rhs : 0; assignVar(ident, val); return val; }
            if (match("&="))  { int64_t val = getVarVal(ident) & parseAssignment(); assignVar(ident, val); return val; }
            if (match("^="))  { int64_t val = getVarVal(ident) ^ parseAssignment(); assignVar(ident, val); return val; }
            if (match("|="))  { int64_t val = getVarVal(ident) | parseAssignment(); assignVar(ident, val); return val; }
            if (match("<<=")) { int64_t val = getVarVal(ident) << parseAssignment(); assignVar(ident, val); return val; }
            if (match(">>=")) { int64_t val = getVarVal(ident) >> parseAssignment(); assignVar(ident, val); return val; }
        }

        m_pos = savePos;
        return parseLogicalOr();
    }

    int64_t parseLogicalOr() {
        int64_t lhs = parseLogicalAnd();
        skipWhitespace();
        while (match("||")) {
            int64_t rhs = parseLogicalAnd();
            lhs = (lhs || rhs) ? 1 : 0;
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseLogicalAnd() {
        int64_t lhs = parseBitwiseOr();
        skipWhitespace();
        while (match("&&")) {
            int64_t rhs = parseBitwiseOr();
            lhs = (lhs && rhs) ? 1 : 0;
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseBitwiseOr() {
        int64_t lhs = parseBitwiseXor();
        skipWhitespace();
        while (m_pos < m_str.size() && m_str[m_pos] == '|' && (m_pos + 1 >= m_str.size() || m_str[m_pos + 1] != '|')) {
            m_pos++;
            int64_t rhs = parseBitwiseXor();
            lhs |= rhs;
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseBitwiseXor() {
        int64_t lhs = parseBitwiseAnd();
        skipWhitespace();
        while (m_pos < m_str.size() && m_str[m_pos] == '^') {
            m_pos++;
            int64_t rhs = parseBitwiseAnd();
            lhs ^= rhs;
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseBitwiseAnd() {
        int64_t lhs = parseEquality();
        skipWhitespace();
        while (m_pos < m_str.size() && m_str[m_pos] == '&' && (m_pos + 1 >= m_str.size() || m_str[m_pos + 1] != '&')) {
            m_pos++;
            int64_t rhs = parseEquality();
            lhs &= rhs;
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseEquality() {
        int64_t lhs = parseRelational();
        skipWhitespace();
        while (true) {
            if (match("==")) {
                lhs = (lhs == parseRelational()) ? 1 : 0;
            } else if (match("!=")) {
                lhs = (lhs != parseRelational()) ? 1 : 0;
            } else {
                break;
            }
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseRelational() {
        int64_t lhs = parseShift();
        skipWhitespace();
        while (true) {
            if (match("<=")) {
                lhs = (lhs <= parseShift()) ? 1 : 0;
            } else if (match(">=")) {
                lhs = (lhs >= parseShift()) ? 1 : 0;
            } else if (match("<")) {
                lhs = (lhs < parseShift()) ? 1 : 0;
            } else if (match(">")) {
                lhs = (lhs > parseShift()) ? 1 : 0;
            } else {
                break;
            }
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseShift() {
        int64_t lhs = parseAdditive();
        skipWhitespace();
        while (true) {
            if (match("<<")) {
                lhs <<= parseAdditive();
            } else if (match(">>")) {
                lhs >>= parseAdditive();
            } else {
                break;
            }
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseAdditive() {
        int64_t lhs = parseMultiplicative();
        skipWhitespace();
        while (m_pos < m_str.size()) {
            if (m_str[m_pos] == '+') {
                m_pos++;
                lhs += parseMultiplicative();
            } else if (m_str[m_pos] == '-') {
                m_pos++;
                lhs -= parseMultiplicative();
            } else {
                break;
            }
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseMultiplicative() {
        int64_t lhs = parseUnary();
        skipWhitespace();
        while (m_pos < m_str.size()) {
            if (m_str[m_pos] == '*') {
                m_pos++;
                lhs *= parseUnary();
            } else if (m_str[m_pos] == '/') {
                m_pos++;
                int64_t rhs = parseUnary();
                lhs = (rhs != 0) ? lhs / rhs : 0;
            } else if (m_str[m_pos] == '%') {
                m_pos++;
                int64_t rhs = parseUnary();
                lhs = (rhs != 0) ? lhs % rhs : 0;
            } else {
                break;
            }
            skipWhitespace();
        }
        return lhs;
    }

    int64_t parseUnary() {
        skipWhitespace();
        if (m_pos < m_str.size()) {
            if (m_str[m_pos] == '+') {
                m_pos++;
                return parseUnary();
            }
            if (m_str[m_pos] == '-') {
                m_pos++;
                return -parseUnary();
            }
            if (m_str[m_pos] == '~') {
                m_pos++;
                return ~parseUnary();
            }
            if (m_str[m_pos] == '!') {
                m_pos++;
                return (!parseUnary()) ? 1 : 0;
            }
        }
        return parsePrimary();
    }

    int64_t parsePrimary() {
        skipWhitespace();
        if (m_pos >= m_str.size()) return 0;

        if (m_str[m_pos] == '(') {
            m_pos++;
            int64_t val = parseCommaExpression();
            skipWhitespace();
            if (m_pos < m_str.size() && m_str[m_pos] == ')') {
                m_pos++;
            }
            return val;
        }

        // Check for number literal
        if (std::isdigit(static_cast<unsigned char>(m_str[m_pos]))) {
            size_t start = m_pos;
            int base = 10;
            if (m_str[m_pos] == '0' && m_pos + 1 < m_str.size() && (m_str[m_pos + 1] == 'x' || m_str[m_pos + 1] == 'X')) {
                base = 16;
                m_pos += 2;
                while (m_pos < m_str.size() && std::isxdigit(static_cast<unsigned char>(m_str[m_pos]))) m_pos++;
            } else if (m_str[m_pos] == '0') {
                base = 8;
                while (m_pos < m_str.size() && m_str[m_pos] >= '0' && m_str[m_pos] <= '7') m_pos++;
            } else {
                while (m_pos < m_str.size() && std::isdigit(static_cast<unsigned char>(m_str[m_pos]))) m_pos++;
            }
            std::string numStr = m_str.substr(start, m_pos - start);
            return std::strtoll(numStr.c_str(), nullptr, base);
        }

        // Check for identifier / variable
        std::string ident;
        if (parseIdentifier(ident)) {
            return getVarVal(ident);
        }

        return 0;
    }

    bool parseIdentifier(std::string& outIdent) {
        skipWhitespace();
        if (m_pos >= m_str.size()) return false;
        char c = m_str[m_pos];
        if (!std::isalpha(static_cast<unsigned char>(c)) && c != '_' && c != '$') return false;

        size_t start = m_pos++;
        while (m_pos < m_str.size()) {
            char ch = m_str[m_pos];
            if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '$') {
                m_pos++;
            } else {
                break;
            }
        }
        outIdent = m_str.substr(start, m_pos - start);
        return true;
    }

    bool match(std::string_view op) {
        skipWhitespace();
        if (m_str.substr(m_pos, op.size()) == op) {
            m_pos += op.size();
            return true;
        }
        return false;
    }

    int64_t getVarVal(const std::string& name) const {
        std::string s;
        if (!m_env.getVar(name, s, m_lastExitCode)) return 0;
        s = trim(s);
        if (s.empty()) return 0;
        return std::strtoll(s.c_str(), nullptr, 0);
    }

    void assignVar(const std::string& name, int64_t val) {
        m_env.setVar(name, std::to_string(val));
    }

    std::string m_str;
    size_t m_pos{0};
    CmdEnvironment& m_env;
    int m_lastExitCode{0};
};

// ============================================================================
// 4. Command Parser & Ast Representation
// ============================================================================

enum class OperatorType {
    None,
    Sequential,     // &
    ConditionalAnd, // &&
    ConditionalOr,  // ||
    Pipe            // |
};

struct SingleCommand {
    std::string rawCommand;
    std::string stdinRedirect;
    std::string stdoutRedirect;
    bool stdoutAppend{false};
    std::string stderrRedirect;
    bool stderrAppend{false};
    bool stderrToStdout{false};
};

struct ChainedCommand {
    SingleCommand command;
    OperatorType op{OperatorType::None};
};

class CmdParser {
public:
    static std::vector<std::string> splitTokens(std::string_view line) {
        std::vector<std::string> tokens;
        std::string current;
        bool inQuotes = false;

        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            if (c == '^' && i + 1 < line.size()) {
                current.push_back(line[++i]);
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
                current.push_back(c);
            } else if ((c == ' ' || c == '\t') && !inQuotes) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) tokens.push_back(current);
        return tokens;
    }

    static std::vector<ChainedCommand> parseCommandLine(std::string_view line) {
        std::vector<ChainedCommand> chain;
        std::string current;
        bool inQuotes = false;
        int parenDepth = 0;

        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            if (c == '^' && i + 1 < line.size()) {
                current.push_back(line[i]);
                current.push_back(line[i + 1]);
                i++;
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
                current.push_back(c);
                continue;
            }
            if (!inQuotes) {
                if (c == '(') parenDepth++;
                if (c == ')') parenDepth = std::max(0, parenDepth - 1);

                if (parenDepth == 0) {
                    if (c == '&' && i + 1 < line.size() && line[i + 1] == '&') {
                        chain.push_back({parseRedirections(current), OperatorType::ConditionalAnd});
                        current.clear();
                        i++;
                        continue;
                    }
                    if (c == '|' && i + 1 < line.size() && line[i + 1] == '|') {
                        chain.push_back({parseRedirections(current), OperatorType::ConditionalOr});
                        current.clear();
                        i++;
                        continue;
                    }
                    if (c == '&') {
                        chain.push_back({parseRedirections(current), OperatorType::Sequential});
                        current.clear();
                        continue;
                    }
                    if (c == '|') {
                        chain.push_back({parseRedirections(current), OperatorType::Pipe});
                        current.clear();
                        continue;
                    }
                }
            }
            current.push_back(c);
        }

        if (!trim(current).empty()) {
            chain.push_back({parseRedirections(current), OperatorType::None});
        }
        return chain;
    }

private:
    static SingleCommand parseRedirections(std::string_view raw) {
        SingleCommand cmd;
        std::string cleaned;
        bool inQuotes = false;

        for (size_t i = 0; i < raw.size(); ++i) {
            char c = raw[i];
            if (c == '^' && i + 1 < raw.size()) {
                cleaned.push_back(raw[i]);
                cleaned.push_back(raw[i + 1]);
                i++;
                continue;
            }
            if (c == '"') {
                inQuotes = !inQuotes;
                cleaned.push_back(c);
                continue;
            }
            if (!inQuotes) {
                // Check 2>&1
                if (c == '2' && i + 3 < raw.size() && raw.substr(i, 4) == "2>&1") {
                    cmd.stderrToStdout = true;
                    i += 3;
                    continue;
                }
                // Check 2>>
                if (c == '2' && i + 2 < raw.size() && raw.substr(i, 3) == "2>>") {
                    cmd.stderrAppend = true;
                    i += 2;
                    cmd.stderrRedirect = extractRedirectTarget(raw, i);
                    continue;
                }
                // Check 2>
                if (c == '2' && i + 1 < raw.size() && raw[i + 1] == '>') {
                    cmd.stderrAppend = false;
                    i += 1;
                    cmd.stderrRedirect = extractRedirectTarget(raw, i);
                    continue;
                }
                // Check >> or 1>>
                if ((c == '>' && i + 1 < raw.size() && raw[i + 1] == '>') ||
                    (c == '1' && i + 2 < raw.size() && raw.substr(i, 3) == "1>>")) {
                    cmd.stdoutAppend = true;
                    i += (c == '1' ? 2 : 1);
                    cmd.stdoutRedirect = extractRedirectTarget(raw, i);
                    continue;
                }
                // Check > or 1>
                if (c == '>' || (c == '1' && i + 1 < raw.size() && raw[i + 1] == '>')) {
                    cmd.stdoutAppend = false;
                    i += (c == '1' ? 1 : 0);
                    cmd.stdoutRedirect = extractRedirectTarget(raw, i);
                    continue;
                }
                // Check <
                if (c == '<') {
                    cmd.stdinRedirect = extractRedirectTarget(raw, i);
                    continue;
                }
            }
            cleaned.push_back(c);
        }
        cmd.rawCommand = trim(cleaned);
        return cmd;
    }

    static std::string extractRedirectTarget(std::string_view s, size_t& i) {
        i++; // skip operator character
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
        std::string target;
        bool inQ = false;
        while (i < s.size()) {
            char c = s[i];
            if (c == '"') {
                inQ = !inQ;
            } else if ((c == ' ' || c == '\t' || c == '&' || c == '|' || c == '<' || c == '>') && !inQ) {
                i--;
                break;
            } else {
                target.push_back(c);
            }
            i++;
        }
        return stripQuotes(target);
    }
};

// ============================================================================
// 5. Batch Script Engine & Call Stack
// ============================================================================

struct BatchCallFrame {
    size_t returnLine{0};
    std::string scriptPath;
    std::vector<std::string> args;
};

// ============================================================================
// 6. Windows CMD Processor & Subsystem Engine (CmdProcessor)
// ============================================================================

class CmdProcessor {
public:
    static CmdProcessor& get() {
        static CmdProcessor s_instance;
        return s_instance;
    }

    CmdProcessor() {
        initializeAssociations();
        registerSystemCmdBinary();
    }

    CmdEnvironment& getEnvironment() noexcept { return m_env; }
    [[nodiscard]] int getLastExitCode() const noexcept { return m_lastExitCode; }
    void setLastExitCode(int code) noexcept { m_lastExitCode = code; }

    std::string getCurrentDirectory() const {
        wchar_t buf[260]{};
        win32::GetCurrentDirectoryW(260, buf);
        std::string s;
        for (int i = 0; buf[i] != L'\0'; ++i) s.push_back(static_cast<char>(buf[i] & 0x7F));
        return s.empty() ? "C:\\" : s;
    }

    std::string getPromptString() const {
        std::string promptFormat;
        if (!m_env.getVar("PROMPT", promptFormat, m_lastExitCode)) {
            promptFormat = "$P$G";
        }
        std::string res;
        for (size_t i = 0; i < promptFormat.size(); ++i) {
            if (promptFormat[i] == '$' && i + 1 < promptFormat.size()) {
                char code = static_cast<char>(std::toupper(static_cast<unsigned char>(promptFormat[++i])));
                if (code == 'P') res += getCurrentDirectory();
                else if (code == 'G') res += '>';
                else if (code == 'D') {
                    std::string d; m_env.getVar("DATE", d, m_lastExitCode); res += d;
                } else if (code == 'T') {
                    std::string t; m_env.getVar("TIME", t, m_lastExitCode); res += t;
                } else if (code == 'V') res += "MicaNT [Version 10.0.26100.1]";
                else if (code == '$') res += '$';
                else if (code == '_') res += '\n';
                else res += promptFormat[i];
            } else {
                res += promptFormat[i];
            }
        }
        return res;
    }

    /**
     * @brief Executes a compound command line with full &, &&, ||, |, redirections.
     */
    int executeCompound(
        std::string_view commandLine,
        std::istream& in = std::cin,
        std::ostream& out = std::cout,
        std::ostream& err = std::cerr
    ) {
        std::string line = trim(commandLine);
        if (line.empty()) return m_lastExitCode;

        // Check for CLI switches e.g. cmd /c <cmd> or cmd /k <cmd>
        if (line.starts_with("cmd ") || line.starts_with("cmd.exe ") || line == "cmd" || line == "cmd.exe") {
            return handleCmdExeInvocation(line, in, out, err);
        }

        auto chained = CmdParser::parseCommandLine(line);
        if (chained.empty()) return m_lastExitCode;

        for (size_t i = 0; i < chained.size(); ++i) {
            auto& node = chained[i];

            // Setup input stream
            std::stringstream pipedInput;
            std::istream* activeIn = &in;
            if (!node.command.stdinRedirect.empty()) {
                std::string fileContent = readVfsTextFile(node.command.stdinRedirect);
                pipedInput.str(fileContent);
                activeIn = &pipedInput;
            }

            // Setup output & error streams
            std::ostringstream capturedOut;
            std::ostringstream capturedErr;
            std::ostream* activeOut = &out;
            std::ostream* activeErr = &err;

            bool isPiped = (node.op == OperatorType::Pipe);
            bool hasOutRedir = !node.command.stdoutRedirect.empty();
            bool hasErrRedir = !node.command.stderrRedirect.empty() || node.command.stderrToStdout;

            if (isPiped || hasOutRedir) {
                activeOut = &capturedOut;
            }
            if (hasErrRedir) {
                activeErr = node.command.stderrToStdout ? activeOut : &capturedErr;
            }

            int rc = executeSingle(node.command.rawCommand, *activeIn, *activeOut, *activeErr);
            m_lastExitCode = rc;

            // Handle output redirection to VFS
            if (hasOutRedir) {
                writeVfsTextFile(node.command.stdoutRedirect, capturedOut.str(), node.command.stdoutAppend);
            }
            if (!node.command.stderrRedirect.empty()) {
                writeVfsTextFile(node.command.stderrRedirect, capturedErr.str(), node.command.stderrAppend);
            }

            // If piped, feed capturedOut to the next command's stdin
            if (isPiped && i + 1 < chained.size()) {
                chained[i + 1].command.stdinRedirect.clear();
                // Execute next with piped input
                std::stringstream nextIn(capturedOut.str());
                std::ostringstream nextOut;
                int nextRc = executeSingle(chained[i + 1].command.rawCommand, nextIn, out, err);
                m_lastExitCode = nextRc;
                i++; // Skip next in loop
                continue;
            }

            // Conditional operators && and ||
            if (node.op == OperatorType::ConditionalAnd) {
                if (rc != 0) break; // Don't execute subsequent && commands on failure
            } else if (node.op == OperatorType::ConditionalOr) {
                if (rc == 0) break; // Don't execute subsequent || commands on success
            }
        }

        return m_lastExitCode;
    }

    /**
     * @brief Executes a single atomic command without compound operators.
     */
    int executeSingle(
        std::string_view rawCmd,
        std::istream& in = std::cin,
        std::ostream& out = std::cout,
        std::ostream& err = std::cerr
    ) {
        std::string expanded = m_env.expandVariables(rawCmd, m_lastExitCode, true);
        std::string line = trim(expanded);
        if (line.empty()) return m_lastExitCode;

        // Strip surrounding parentheses if any
        if (line.front() == '(' && line.back() == ')') {
            line = trim(line.substr(1, line.size() - 2));
            return executeCompound(line, in, out, err);
        }

        // Check for REM or :: comment
        if (line.starts_with("::") || iequals(line.substr(0, 4), "rem ") || line == "rem") {
            return 0;
        }

        auto tokens = CmdParser::splitTokens(line);
        if (tokens.empty()) return 0;

        std::string cmd = toLower(tokens[0]);

        // Builtin Command Dispatch Table
        if (cmd == "exit") {
            return cmdExit(tokens, out);
        } else if (cmd == "echo") {
            return cmdEcho(tokens, line, out);
        } else if (cmd == "set") {
            return cmdSet(tokens, line, in, out);
        } else if (cmd == "setlocal") {
            return cmdSetlocal(tokens, out);
        } else if (cmd == "endlocal") {
            return cmdEndlocal(out);
        } else if (cmd == "dir" || cmd == "ls") {
            return cmdDir(tokens, out);
        } else if (cmd == "cd" || cmd == "chdir") {
            return cmdCd(tokens, out);
        } else if (cmd == "md" || cmd == "mkdir") {
            return cmdMkdir(tokens, out);
        } else if (cmd == "rd" || cmd == "rmdir") {
            return cmdRmdir(tokens, out);
        } else if (cmd == "del" || cmd == "erase") {
            return cmdDel(tokens, out);
        } else if (cmd == "copy") {
            return cmdCopy(tokens, out);
        } else if (cmd == "xcopy") {
            return cmdXcopy(tokens, out);
        } else if (cmd == "ren" || cmd == "rename") {
            return cmdRen(tokens, out);
        } else if (cmd == "move") {
            return cmdMove(tokens, out);
        } else if (cmd == "type" || cmd == "cat") {
            return cmdType(tokens, in, out);
        } else if (cmd == "more") {
            return cmdMore(tokens, in, out);
        } else if (cmd == "find") {
            return cmdFind(tokens, in, out);
        } else if (cmd == "findstr") {
            return cmdFindstr(tokens, in, out);
        } else if (cmd == "sort") {
            return cmdSort(tokens, in, out);
        } else if (cmd == "where") {
            return cmdWhere(tokens, out);
        } else if (cmd == "attrib") {
            return cmdAttrib(tokens, out);
        } else if (cmd == "tree") {
            return cmdTree(tokens, out);
        } else if (cmd == "if") {
            return cmdIf(line, in, out, err);
        } else if (cmd == "for") {
            return cmdFor(line, in, out, err);
        } else if (cmd == "title") {
            return cmdTitle(tokens, line);
        } else if (cmd == "color") {
            return cmdColor(tokens, out);
        } else if (cmd == "path") {
            return cmdPath(tokens, out);
        } else if (cmd == "prompt") {
            return cmdPrompt(tokens, line);
        } else if (cmd == "vol") {
            return cmdVol(tokens, out);
        } else if (cmd == "label") {
            return cmdLabel(tokens, out);
        } else if (cmd == "date") {
            return cmdDate(tokens, out);
        } else if (cmd == "time") {
            return cmdTime(tokens, out);
        } else if (cmd == "pause") {
            out << "Press any key to continue . . .\n";
            return 0;
        } else if (cmd == "timeout") {
            return cmdTimeout(tokens, out);
        } else if (cmd == "choice") {
            return cmdChoice(tokens, in, out);
        } else if (cmd == "tasklist") {
            return cmdTasklist(out);
        } else if (cmd == "taskkill") {
            return cmdTaskkill(tokens, out);
        } else if (cmd == "start") {
            return cmdStart(tokens, line, out);
        } else if (cmd == "assoc") {
            return cmdAssoc(tokens, out);
        } else if (cmd == "ftype") {
            return cmdFtype(tokens, out);
        } else if (cmd == "ver") {
            out << "\nMicaNT [Version 10.0.26100.1]\n(c) Project MICA. Dave Cutler Clean-Room Executive.\n\n";
            return 0;
        } else if (cmd == "cls" || cmd == "clear") {
            out << "\033[2J\033[H";
            return 0;
        } else if (cmd == "help" || cmd == "?") {
            printHelp(out);
            return 0;
        }

        // Check if command is a batch file (.bat or .cmd)
        std::string scriptPath = resolveExecutablePath(tokens[0]);
        if (scriptPath.ends_with(".bat") || scriptPath.ends_with(".cmd")) {
            std::vector<std::string> args(tokens.begin() + 1, tokens.end());
            return executeBatchFile(scriptPath, args, in, out, err);
        }

        // Check if command is an executable registered or on VFS
        if (scriptPath.ends_with(".exe") || canRunBinary(scriptPath)) {
            return runExternalBinary(scriptPath, tokens, out);
        }

        err << "'" << tokens[0] << "' is not recognized as an internal or external command,\n"
            << "operable program or batch file.\n";
        return 9009; // ERROR_BAD_COMMAND_OR_FILE
    }

    /**
     * @brief Executes a Windows Batch script (.bat / .cmd) with full call stack & flow control.
     */
    int executeBatchFile(
        const std::string& filePath,
        const std::vector<std::string>& arguments,
        std::istream& in = std::cin,
        std::ostream& out = std::cout,
        std::ostream& err = std::cerr
    ) {
        std::string scriptText = readVfsTextFile(filePath);
        if (scriptText.empty()) {
            err << "The system cannot find the batch file specified: " << filePath << "\n";
            return 2;
        }

        std::vector<std::string> lines = splitLines(scriptText);
        std::unordered_map<std::string, size_t> labels;

        // Index all :LABEL lines
        for (size_t i = 0; i < lines.size(); ++i) {
            std::string trimmed = trim(lines[i]);
            if (trimmed.starts_with(":") && !trimmed.starts_with("::")) {
                std::string labelName = toUpper(trim(trimmed.substr(1)));
                size_t spacePos = labelName.find_first_of(" \t");
                if (spacePos != std::string::npos) labelName = labelName.substr(0, spacePos);
                labels[labelName] = i;
            }
        }

        // Call stack for CALL :label
        std::stack<BatchCallFrame> callStack;

        // Scope stack guard count
        size_t initialScopeDepth = m_env.getAllVars().size();
        (void)initialScopeDepth;

        // Current frame parameters
        std::vector<std::string> currentArgs = arguments;
        std::string currentScriptPath = filePath;
        size_t currentLine = 0;
        bool echoOn = true;

        while (currentLine < lines.size()) {
            std::string line = lines[currentLine];
            std::string trimmed = trim(line);
            currentLine++;

            if (trimmed.empty()) continue;

            // Handle line echo suppression (@ prefix)
            bool suppressEcho = false;
            if (trimmed.front() == '@') {
                suppressEcho = true;
                trimmed = trim(trimmed.substr(1));
            }

            if (trimmed.empty()) continue;

            // Check if comment or label
            if (trimmed.starts_with("::") || iequals(trimmed.substr(0, 4), "rem ") || trimmed == "rem") {
                continue;
            }
            if (trimmed.starts_with(":")) {
                continue; // Label definition line
            }

            // Check for @echo off / @echo on
            if (iequals(trimmed, "echo off")) {
                echoOn = false;
                continue;
            } else if (iequals(trimmed, "echo on")) {
                echoOn = true;
                continue;
            }

            // Batch parameter substitution: %0..%9, %*, %~dp0, %~nx0, %~f0, %~1
            std::string expandedLine = substituteBatchParameters(trimmed, currentScriptPath, currentArgs);

            // Variable expansion
            expandedLine = m_env.expandVariables(expandedLine, m_lastExitCode, true);

            // Handle multi-line block grouping with parentheses if line ends with '('
            if (expandedLine.ends_with("(") && !expandedLine.ends_with("^(")) {
                std::string block = expandedLine + "\n";
                int depth = 1;
                while (currentLine < lines.size() && depth > 0) {
                    std::string nextL = lines[currentLine++];
                    for (char c : nextL) {
                        if (c == '(') depth++;
                        else if (c == ')') depth--;
                    }
                    block += nextL + "\n";
                }
                expandedLine = trim(block);
            }

            if (echoOn && !suppressEcho) {
                out << getCurrentDirectory() << ">" << expandedLine << "\n";
            }

            // Flow control commands: GOTO, CALL, SHIFT, EXIT /B
            auto tokens = CmdParser::splitTokens(expandedLine);
            if (!tokens.empty()) {
                std::string first = toLower(tokens[0]);

                if (first == "goto" && tokens.size() > 1) {
                    std::string target = toUpper(tokens[1]);
                    if (target.starts_with(":")) target = target.substr(1);
                    if (target == "EOF") {
                        if (!callStack.empty()) {
                            auto frame = callStack.top();
                            callStack.pop();
                            currentLine = frame.returnLine;
                            currentScriptPath = frame.scriptPath;
                            currentArgs = frame.args;
                            continue;
                        } else {
                            break; // Exit batch script
                        }
                    }
                    auto it = labels.find(target);
                    if (it != labels.end()) {
                        currentLine = it->second + 1;
                    } else {
                        err << "The system cannot find the batch label specified - " << target << "\n";
                        m_lastExitCode = 1;
                    }
                    continue;
                }

                if (first == "call" && tokens.size() > 1) {
                    if (tokens[1].starts_with(":")) {
                        // Subroutine call within same script
                        std::string target = toUpper(tokens[1].substr(1));
                        auto it = labels.find(target);
                        if (it != labels.end()) {
                            BatchCallFrame frame;
                            frame.returnLine = currentLine;
                            frame.scriptPath = currentScriptPath;
                            frame.args = currentArgs;
                            callStack.push(frame);

                            currentArgs = std::vector<std::string>(tokens.begin() + 2, tokens.end());
                            currentLine = it->second + 1;
                        } else {
                            err << "The system cannot find the batch label specified - " << target << "\n";
                            m_lastExitCode = 1;
                        }
                        continue;
                    } else {
                        // External batch or binary call
                        std::vector<std::string> subArgs(tokens.begin() + 2, tokens.end());
                        std::string subScript = resolveExecutablePath(tokens[1]);
                        if (subScript.ends_with(".bat") || subScript.ends_with(".cmd")) {
                            m_lastExitCode = executeBatchFile(subScript, subArgs, in, out, err);
                        } else {
                            m_lastExitCode = executeCompound(expandedLine.substr(5), in, out, err);
                        }
                        continue;
                    }
                }

                if (first == "shift") {
                    if (!currentArgs.empty()) {
                        currentArgs.erase(currentArgs.begin());
                    }
                    continue;
                }

                if (first == "exit") {
                    bool isBatchExit = false;
                    int exitCode = m_lastExitCode;
                    for (size_t a = 1; a < tokens.size(); ++a) {
                        if (iequals(tokens[a], "/b")) {
                            isBatchExit = true;
                        } else {
                            exitCode = static_cast<int>(std::strtol(tokens[a].c_str(), nullptr, 10));
                        }
                    }
                    m_lastExitCode = exitCode;
                    if (isBatchExit) {
                        if (!callStack.empty()) {
                            auto frame = callStack.top();
                            callStack.pop();
                            currentLine = frame.returnLine;
                            currentScriptPath = frame.scriptPath;
                            currentArgs = frame.args;
                            continue;
                        } else {
                            break; // Exit batch script
                        }
                    } else {
                        return exitCode; // Exit command shell entirely
                    }
                }
            }

            // Normal command line execution
            executeCompound(expandedLine, in, out, err);
        }

        return m_lastExitCode;
    }

private:
    // ========================================================================
    // Internal Built-in Commands Implementation
    // ========================================================================

    int cmdExit(const std::vector<std::string>& tokens, std::ostream& /*out*/) {
        int code = m_lastExitCode;
        bool bFlag = false;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/b")) bFlag = true;
            else code = static_cast<int>(std::strtol(tokens[i].c_str(), nullptr, 10));
        }
        m_lastExitCode = code;
        return bFlag ? code : -1; // -1 signals REPL exit
    }

    int cmdEcho(const std::vector<std::string>& tokens, const std::string& fullLine, std::ostream& out) {
        if (tokens.size() == 1) {
            out << "ECHO is on.\n";
            return 0;
        }
        if (tokens.size() == 2) {
            if (iequals(tokens[1], "on")) { return 0; }
            if (iequals(tokens[1], "off")) { return 0; }
        }

        // Handle echo. or echo: for empty line
        if (fullLine.size() >= 5 && (fullLine[4] == '.' || fullLine[4] == ':' || fullLine[4] == '/')) {
            std::string rest = fullLine.substr(5);
            if (trim(rest).empty()) {
                out << "\n";
                return 0;
            }
        }

        size_t pos = fullLine.find_first_not_of(" \t", 4);
        if (pos == std::string::npos) {
            out << "\n";
            return 0;
        }

        std::string text = fullLine.substr(pos);
        out << text << "\n";
        return 0;
    }

    int cmdSet(const std::vector<std::string>& tokens, const std::string& fullLine, std::istream& in, std::ostream& out) {
        if (tokens.size() == 1) {
            auto all = m_env.getAllVars();
            for (const auto& [k, v] : all) {
                out << k << "=" << v << "\n";
            }
            return 0;
        }

        // Check for SET /A (Arithmetic expression)
        if (iequals(tokens[1], "/a")) {
            size_t slashPos = fullLine.find_first_of("/a/A");
            std::string expr = (slashPos != std::string::npos) ? fullLine.substr(slashPos + 2) : "";
            int64_t result = SetArithmetic::evaluate(expr, m_env, m_lastExitCode);
            // If expression did not contain an assignment, print the value
            if (expr.find('=') == std::string::npos) {
                out << result << "\n";
            }
            return 0;
        }

        // Check for SET /P (Prompt user for input)
        if (iequals(tokens[1], "/p")) {
            size_t pPos = fullLine.find_first_of("/p/P");
            std::string rest = (pPos != std::string::npos) ? trim(fullLine.substr(pPos + 2)) : "";
            size_t eqPos = rest.find('=');
            if (eqPos != std::string::npos) {
                std::string varName = trim(rest.substr(0, eqPos));
                std::string promptMsg = rest.substr(eqPos + 1);
                out << promptMsg << std::flush;
                std::string inputVal;
                if (std::getline(in, inputVal)) {
                    m_env.setVar(varName, trim(inputVal));
                }
            }
            return 0;
        }

        // Standard SET VAR=VALUE or SET VAR
        size_t pos = fullLine.find_first_not_of(" \t", 3);
        if (pos == std::string::npos) return 0;
        std::string expr = fullLine.substr(pos);
        size_t eqPos = expr.find('=');
        if (eqPos == std::string::npos) {
            // Display variables starting with prefix
            std::string prefix = toUpper(trim(expr));
            auto all = m_env.getAllVars();
            bool found = false;
            for (const auto& [k, v] : all) {
                if (k.starts_with(prefix)) {
                    out << k << "=" << v << "\n";
                    found = true;
                }
            }
            if (!found) {
                out << "Environment variable " << expr << " not defined\n";
                return 1;
            }
        } else {
            std::string varName = trim(expr.substr(0, eqPos));
            std::string varVal = expr.substr(eqPos + 1);
            m_env.setVar(varName, varVal);
        }
        return 0;
    }

    int cmdSetlocal(const std::vector<std::string>& tokens, std::ostream& /*out*/) {
        bool delayed = m_env.isDelayedExpansionEnabled();
        bool ext = m_env.areExtensionsEnabled();
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "EnableDelayedExpansion")) delayed = true;
            else if (iequals(tokens[i], "DisableDelayedExpansion")) delayed = false;
            else if (iequals(tokens[i], "EnableExtensions")) ext = true;
            else if (iequals(tokens[i], "DisableExtensions")) ext = false;
        }
        m_env.pushScope(delayed, ext);
        return 0;
    }

    int cmdEndlocal(std::ostream& /*out*/) {
        return m_env.popScope() ? 0 : 1;
    }

    int cmdDir(const std::vector<std::string>& tokens, std::ostream& out) {
        std::string target = getCurrentDirectory();
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) {
                target = tokens[i];
                break;
            }
        }

        std::wstring wTarget(target.begin(), target.end());
        std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
        NtStatus st = fs::VirtualFileSystem::get().queryDirectory(wTarget, entries);
        if (!NT_SUCCESS(st)) {
            out << "File Not Found: " << target << "\n";
            return 1;
        }

        out << " Directory of " << target << "\n\n";
        size_t totalFiles = 0;
        size_t totalDirs = 0;
        size_t totalBytes = 0;

        for (const auto& e : entries) {
            std::string name;
            for (wchar_t wc : e.name) name.push_back(static_cast<char>(wc & 0x7F));
            out << "10/01/2026  12:00 PM    ";
            if (e.isDirectory) {
                out << "<DIR>          ";
                totalDirs++;
            } else {
                out << std::setw(14) << e.size << " ";
                totalFiles++;
                totalBytes += e.size;
            }
            out << name << "\n";
        }
        out << "               " << totalFiles << " File(s)    " << totalBytes << " bytes\n";
        out << "               " << totalDirs << " Dir(s)     2,629,282,086,912 bytes free\n";
        return 0;
    }

    int cmdCd(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) {
            out << getCurrentDirectory() << "\n";
            return 0;
        }

        std::string target = tokens[1];
        if (target == "..") {
            std::string cur = getCurrentDirectory();
            size_t slash = cur.find_last_of("\\/");
            if (slash != std::string::npos && slash > 2) {
                target = cur.substr(0, slash);
            } else if (slash == 2) {
                target = cur.substr(0, 3);
            }
        }

        std::wstring wTarget(target.begin(), target.end());
        if (win32::SetCurrentDirectoryW(wTarget.c_str())) {
            return 0;
        } else {
            out << "The system cannot find the path specified: " << target << "\n";
            return 1;
        }
    }

    int cmdMkdir(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i].starts_with("/")) continue;
            std::string dirPath = tokens[i];
            std::wstring wDir(dirPath.begin(), dirPath.end());
            if (!win32::CreateDirectoryW(wDir.c_str(), nullptr)) {
                // If collision, ignore in Windows MKDIR
                if (win32::GetLastError() != 80 && win32::GetLastError() != 183) {
                    out << "A subdirectory or file " << dirPath << " already exists or cannot be created.\n";
                }
            }
        }
        return 0;
    }

    int cmdRmdir(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        bool recursive = false;
        std::string target;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/s")) recursive = true;
            else if (iequals(tokens[i], "/q")) {}
            else if (!tokens[i].starts_with("/")) target = tokens[i];
        }

        if (target.empty()) return 1;

        std::wstring wDir(target.begin(), target.end());
        NtStatus st = recursive 
            ? fs::VirtualFileSystem::get().removeDirectoryRecursive(wDir)
            : fs::VirtualFileSystem::get().removeDirectory(wDir);

        if (!NT_SUCCESS(st)) {
            out << "The system cannot find the path specified: " << target << "\n";
            return 1;
        }
        return 0;
    }

    int cmdDel(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        std::vector<std::string> targets;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i].starts_with("/")) continue;
            targets.push_back(tokens[i]);
        }

        if (targets.empty()) return 1;

        for (const auto& pattern : targets) {
            // Check for wildcards
            if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
                deleteWildcard(pattern);
            } else {
                std::wstring wPath(pattern.begin(), pattern.end());
                if (!win32::DeleteFileW(wPath.c_str())) {
                    out << "Could Not Find " << pattern << "\n";
                    return 1;
                }
            }
        }
        return 0;
    }

    void deleteWildcard(const std::string& pattern) {
        std::string dir = getCurrentDirectory();
        std::string filePat = pattern;
        size_t slash = pattern.find_last_of("\\/");
        if (slash != std::string::npos) {
            dir = pattern.substr(0, slash);
            filePat = pattern.substr(slash + 1);
        }

        std::wstring wDir(dir.begin(), dir.end());
        std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
        if (NT_SUCCESS(fs::VirtualFileSystem::get().queryDirectory(wDir, entries))) {
            for (const auto& e : entries) {
                if (!e.isDirectory) {
                    std::string name;
                    for (wchar_t wc : e.name) name.push_back(static_cast<char>(wc & 0x7F));
                    if (wildcardMatch(filePat, name)) {
                        std::string fullTarget = dir + "\\" + name;
                        std::wstring wFull(fullTarget.begin(), fullTarget.end());
                        win32::DeleteFileW(wFull.c_str());
                    }
                }
            }
        }
    }

    int cmdCopy(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 3) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        std::vector<std::string> paths;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) paths.push_back(tokens[i]);
        }
        if (paths.size() < 2) return 1;

        std::string src = paths[0];
        std::string dst = paths[1];

        // If dst is a directory or ends with slash, append src filename
        uint32_t dstAttrs = 0;
        std::wstring wDst(dst.begin(), dst.end());
        if (dst.ends_with("\\") || dst.ends_with("/") ||
            (NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(wDst, dstAttrs)) && (dstAttrs & fs::FILE_ATTRIBUTE_DIRECTORY))) {
            size_t slash = src.find_last_of("\\/");
            std::string srcName = (slash == std::string::npos) ? src : src.substr(slash + 1);
            if (!dst.ends_with("\\") && !dst.ends_with("/")) dst += "\\";
            dst += srcName;
            wDst = std::wstring(dst.begin(), dst.end());
        }

        std::wstring wSrc(src.begin(), src.end());
        if (win32::CopyFileW(wSrc.c_str(), wDst.c_str(), win32::FALSE)) {
            out << "        1 file(s) copied.\n";
            return 0;
        } else {
            out << "The system cannot find the file specified.\n";
            return 1;
        }
    }

    int cmdXcopy(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 3) {
            out << "Invalid number of parameters\n";
            return 1;
        }
        std::vector<std::string> paths;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) paths.push_back(tokens[i]);
        }
        if (paths.size() < 2) return 1;

        std::string src = paths[0];
        std::string dst = paths[1];
        size_t count = 0;
        xcopyRecursive(src, dst, count);
        out << "        " << count << " File(s) copied\n";
        return 0;
    }

    void xcopyRecursive(const std::string& src, const std::string& dst, size_t& count) {
        std::wstring wSrc(src.begin(), src.end());
        uint32_t attrs = 0;
        if (!NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(wSrc, attrs))) return;

        if (!(attrs & fs::FILE_ATTRIBUTE_DIRECTORY)) {
            std::string targetFile = dst;
            if (dst.ends_with("\\") || dst.ends_with("/")) {
                size_t slash = src.find_last_of("\\/");
                std::string fname = (slash == std::string::npos) ? src : src.substr(slash + 1);
                targetFile = dst + fname;
            }
            std::wstring wDst(targetFile.begin(), targetFile.end());
            if (win32::CopyFileW(wSrc.c_str(), wDst.c_str(), win32::FALSE)) {
                count++;
            }
            return;
        }

        // Directory copy
        std::wstring wDstDir(dst.begin(), dst.end());
        win32::CreateDirectoryW(wDstDir.c_str(), nullptr);

        std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
        if (NT_SUCCESS(fs::VirtualFileSystem::get().queryDirectory(wSrc, entries))) {
            for (const auto& e : entries) {
                std::string name;
                for (wchar_t wc : e.name) name.push_back(static_cast<char>(wc & 0x7F));
                std::string subSrc = src + "\\" + name;
                std::string subDst = dst + "\\" + name;
                xcopyRecursive(subSrc, subDst, count);
            }
        }
    }

    int cmdRen(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 3) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        std::string oldPath = tokens[1];
        std::string newName = tokens[2];

        // newName shouldn't contain directory components
        size_t slash = oldPath.find_last_of("\\/");
        std::string parent = (slash == std::string::npos) ? "" : oldPath.substr(0, slash + 1);
        std::string targetNew = parent + newName;

        std::wstring wOld(oldPath.begin(), oldPath.end());
        std::wstring wNew(targetNew.begin(), targetNew.end());
        if (win32::MoveFileW(wOld.c_str(), wNew.c_str())) {
            return 0;
        } else {
            out << "The system cannot find the file specified.\n";
            return 1;
        }
    }

    int cmdMove(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 3) {
            out << "The syntax of the command is incorrect.\n";
            return 1;
        }
        std::vector<std::string> paths;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) paths.push_back(tokens[i]);
        }
        if (paths.size() < 2) return 1;

        std::string src = paths[0];
        std::string dst = paths[1];

        std::wstring wDst(dst.begin(), dst.end());
        uint32_t dstAttrs = 0;
        if (dst.ends_with("\\") || dst.ends_with("/") ||
            (NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(wDst, dstAttrs)) && (dstAttrs & fs::FILE_ATTRIBUTE_DIRECTORY))) {
            size_t slash = src.find_last_of("\\/");
            std::string srcName = (slash == std::string::npos) ? src : src.substr(slash + 1);
            if (!dst.ends_with("\\") && !dst.ends_with("/")) dst += "\\";
            dst += srcName;
            wDst = std::wstring(dst.begin(), dst.end());
        }

        std::wstring wSrc(src.begin(), src.end());
        if (win32::MoveFileW(wSrc.c_str(), wDst.c_str())) {
            out << "        1 file(s) moved.\n";
            return 0;
        } else {
            out << "The system cannot find the file specified.\n";
            return 1;
        }
    }

    int cmdType(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        if (tokens.size() < 2) {
            // Echo stdin to stdout
            std::string line;
            while (std::getline(in, line)) {
                out << line << "\n";
            }
            return 0;
        }

        for (size_t i = 1; i < tokens.size(); ++i) {
            std::string content = readVfsTextFile(tokens[i]);
            if (content.empty()) {
                out << "The system cannot find the file specified: " << tokens[i] << "\n";
                return 1;
            }
            out << content;
            if (!content.empty() && content.back() != '\n') out << "\n";
        }
        return 0;
    }

    int cmdMore(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        if (tokens.size() > 1) {
            return cmdType(tokens, in, out);
        }
        std::string line;
        while (std::getline(in, line)) {
            out << line << "\n";
        }
        return 0;
    }

    int cmdFind(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        bool invert = false;
        bool countOnly = false;
        bool ignoreCase = false;
        bool lineNumbers = false;
        std::string pattern;
        std::vector<std::string> files;

        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/v")) invert = true;
            else if (iequals(tokens[i], "/c")) countOnly = true;
            else if (iequals(tokens[i], "/i")) ignoreCase = true;
            else if (iequals(tokens[i], "/n")) lineNumbers = true;
            else if (pattern.empty()) pattern = stripQuotes(tokens[i]);
            else files.push_back(tokens[i]);
        }

        if (pattern.empty()) {
            out << "FIND: Parameter format not correct\n";
            return 2;
        }

        auto searchInStream = [&](std::istream& stream, const std::string& title) -> int {
            if (!title.empty()) out << "\n---------- " << title << "\n";
            std::string l;
            size_t matchCount = 0;
            size_t lineIdx = 0;
            std::string patCmp = ignoreCase ? toLower(pattern) : pattern;

            while (std::getline(stream, l)) {
                lineIdx++;
                std::string lineCmp = ignoreCase ? toLower(l) : l;
                bool found = (lineCmp.find(patCmp) != std::string::npos);
                if (invert) found = !found;

                if (found) {
                    matchCount++;
                    if (!countOnly) {
                        if (lineNumbers) out << "[" << lineIdx << "]";
                        out << l << "\n";
                    }
                }
            }
            if (countOnly) {
                out << matchCount << "\n";
            }
            return (matchCount > 0) ? 0 : 1;
        };

        if (files.empty()) {
            return searchInStream(in, "");
        } else {
            int ret = 1;
            for (const auto& f : files) {
                std::string content = readVfsTextFile(f);
                std::stringstream ss(content);
                int r = searchInStream(ss, f);
                if (r == 0) ret = 0;
            }
            return ret;
        }
    }

    int cmdFindstr(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        bool ignoreCase = false;
        bool lineNumbers = false;
        std::string pattern;
        std::vector<std::string> files;

        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/i")) ignoreCase = true;
            else if (iequals(tokens[i], "/n")) lineNumbers = true;
            else if (tokens[i].starts_with("/")) {}
            else if (pattern.empty()) pattern = stripQuotes(tokens[i]);
            else files.push_back(tokens[i]);
        }

        if (pattern.empty()) return 2;

        std::string patCmp = ignoreCase ? toLower(pattern) : pattern;
        auto processStream = [&](std::istream& strm) -> int {
            std::string line;
            size_t lineNum = 0;
            int foundAny = 1;
            while (std::getline(strm, line)) {
                lineNum++;
                std::string check = ignoreCase ? toLower(line) : line;
                if (check.find(patCmp) != std::string::npos) {
                    foundAny = 0;
                    if (lineNumbers) out << lineNum << ":";
                    out << line << "\n";
                }
            }
            return foundAny;
        };

        if (files.empty()) {
            return processStream(in);
        } else {
            int ret = 1;
            for (const auto& f : files) {
                std::string content = readVfsTextFile(f);
                std::stringstream ss(content);
                if (processStream(ss) == 0) ret = 0;
            }
            return ret;
        }
    }

    int cmdSort(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        bool reverse = false;
        std::string file;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/r")) reverse = true;
            else if (!tokens[i].starts_with("/")) file = tokens[i];
        }

        std::vector<std::string> lines;
        if (!file.empty()) {
            std::string content = readVfsTextFile(file);
            std::stringstream ss(content);
            std::string l;
            while (std::getline(ss, l)) lines.push_back(l);
        } else {
            std::string l;
            while (std::getline(in, l)) lines.push_back(l);
        }

        std::sort(lines.begin(), lines.end());
        if (reverse) std::reverse(lines.begin(), lines.end());

        for (const auto& l : lines) out << l << "\n";
        return 0;
    }

    int cmdWhere(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) return 1;
        std::string pattern = stripQuotes(tokens.back());
        std::vector<std::string> found;

        // 1. Search current directory
        searchDirectoryForFiles(getCurrentDirectory(), pattern, found);

        // 2. Search PATH directories
        std::string pathVar;
        if (m_env.getVar("PATH", pathVar, m_lastExitCode)) {
            std::stringstream ss(pathVar);
            std::string dir;
            while (std::getline(ss, dir, ';')) {
                dir = trim(dir);
                if (!dir.empty()) {
                    searchDirectoryForFiles(dir, pattern, found);
                }
            }
        }

        if (found.empty()) {
            out << "INFO: Could not find files for the given pattern(s).\n";
            return 1;
        }

        for (const auto& f : found) out << f << "\n";
        return 0;
    }

    void searchDirectoryForFiles(const std::string& dir, const std::string& pattern, std::vector<std::string>& outList) {
        std::wstring wDir(dir.begin(), dir.end());
        std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
        if (NT_SUCCESS(fs::VirtualFileSystem::get().queryDirectory(wDir, entries))) {
            for (const auto& e : entries) {
                if (!e.isDirectory) {
                    std::string name;
                    for (wchar_t wc : e.name) name.push_back(static_cast<char>(wc & 0x7F));
                    if (wildcardMatch(pattern, name) || iequals(pattern, name)) {
                        std::string full = dir;
                        if (!full.ends_with("\\") && !full.ends_with("/")) full += "\\";
                        full += name;
                        if (std::find(outList.begin(), outList.end(), full) == outList.end()) {
                            outList.push_back(full);
                        }
                    }
                }
            }
        }
    }

    int cmdAttrib(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() == 1) {
            return cmdDir(tokens, out);
        }

        std::string target;
        std::vector<std::string> flags;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i].starts_with("+") || tokens[i].starts_with("-")) {
                flags.push_back(toUpper(tokens[i]));
            } else {
                target = tokens[i];
            }
        }

        if (target.empty()) target = "*.*";
        std::wstring wTarget(target.begin(), target.end());

        uint32_t currentAttrs = 0;
        if (!NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(wTarget, currentAttrs))) {
            out << "File not found - " << target << "\n";
            return 1;
        }

        if (flags.empty()) {
            // Display attributes
            out << ((currentAttrs & fs::FILE_ATTRIBUTE_NORMAL) ? "A" : " ") << "  "
                << ((currentAttrs & fs::FILE_ATTRIBUTE_READONLY) ? "R" : " ") << "  "
                << ((currentAttrs & fs::FILE_ATTRIBUTE_HIDDEN) ? "H" : " ") << "  "
                << ((currentAttrs & fs::FILE_ATTRIBUTE_SYSTEM) ? "S" : " ") << "    "
                << target << "\n";
            return 0;
        }

        for (const auto& f : flags) {
            bool setBit = (f[0] == '+');
            char attrChar = (f.size() > 1) ? f[1] : ' ';
            if (attrChar == 'R') {
                if (setBit) currentAttrs |= fs::FILE_ATTRIBUTE_READONLY;
                else currentAttrs &= ~fs::FILE_ATTRIBUTE_READONLY;
            } else if (attrChar == 'H') {
                if (setBit) currentAttrs |= fs::FILE_ATTRIBUTE_HIDDEN;
                else currentAttrs &= ~fs::FILE_ATTRIBUTE_HIDDEN;
            } else if (attrChar == 'S') {
                if (setBit) currentAttrs |= fs::FILE_ATTRIBUTE_SYSTEM;
                else currentAttrs &= ~fs::FILE_ATTRIBUTE_SYSTEM;
            }
        }

        fs::VirtualFileSystem::get().setFileAttributes(wTarget, currentAttrs);
        return 0;
    }

    int cmdTree(const std::vector<std::string>& tokens, std::ostream& out) {
        std::string startPath = getCurrentDirectory();
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) startPath = tokens[i];
        }

        out << "Folder PATH listing for volume MICANT_SYS\n";
        out << "Volume serial number is 1337-BEEF\n";
        out << startPath << "\n";
        printTreeRecursive(startPath, "", out);
        return 0;
    }

    void printTreeRecursive(const std::string& path, const std::string& prefix, std::ostream& out) {
        std::wstring wPath(path.begin(), path.end());
        std::vector<fs::VirtualFileSystem::DirectoryEntry> entries;
        if (!NT_SUCCESS(fs::VirtualFileSystem::get().queryDirectory(wPath, entries))) return;

        std::vector<std::string> subdirs;
        for (const auto& e : entries) {
            if (e.isDirectory) {
                std::string n;
                for (wchar_t c : e.name) n.push_back(static_cast<char>(c & 0x7F));
                subdirs.push_back(n);
            }
        }

        for (size_t i = 0; i < subdirs.size(); ++i) {
            bool isLast = (i + 1 == subdirs.size());
            out << prefix << (isLast ? "\\---" : "+---") << subdirs[i] << "\n";
            printTreeRecursive(path + "\\" + subdirs[i], prefix + (isLast ? "    " : "|   "), out);
        }
    }

    int cmdIf(
        std::string_view fullLine,
        std::istream& in,
        std::ostream& out,
        std::ostream& err
    ) {
        std::string s = trim(fullLine);
        if (!iequals(s.substr(0, 3), "if ") && !iequals(s.substr(0, 3), "if\t")) return 1;
        std::string rest = trim(s.substr(2));

        bool ignoreCase = false;
        if (iequals(rest.substr(0, 3), "/i ") || iequals(rest.substr(0, 3), "/i\t")) {
            ignoreCase = true;
            rest = trim(rest.substr(3));
        }

        bool notFlag = false;
        if (iequals(rest.substr(0, 4), "not ") || iequals(rest.substr(0, 4), "not\t")) {
            notFlag = true;
            rest = trim(rest.substr(4));
        }

        bool conditionMet = false;
        std::string thenCmd;
        std::string elseCmd;

        if (iequals(rest.substr(0, 6), "exist ") || iequals(rest.substr(0, 6), "exist\t")) {
            rest = trim(rest.substr(6));
            auto tokens = CmdParser::splitTokens(rest);
            if (tokens.empty()) return 1;
            std::string path = stripQuotes(tokens[0]);
            conditionMet = vfsFileExists(path);

            size_t thenPos = rest.find(tokens[0]) + tokens[0].size();
            splitThenElse(rest.substr(thenPos), thenCmd, elseCmd);
        } else if (iequals(rest.substr(0, 8), "defined ") || iequals(rest.substr(0, 8), "defined\t")) {
            rest = trim(rest.substr(8));
            auto tokens = CmdParser::splitTokens(rest);
            if (tokens.empty()) return 1;
            std::string varName = stripQuotes(tokens[0]);
            conditionMet = m_env.isDefined(varName, m_lastExitCode);

            size_t thenPos = rest.find(tokens[0]) + tokens[0].size();
            splitThenElse(rest.substr(thenPos), thenCmd, elseCmd);
        } else if (iequals(rest.substr(0, 11), "errorlevel ") || iequals(rest.substr(0, 11), "errorlevel\t")) {
            rest = trim(rest.substr(11));
            auto tokens = CmdParser::splitTokens(rest);
            if (tokens.empty()) return 1;
            int reqLevel = static_cast<int>(std::strtol(tokens[0].c_str(), nullptr, 10));
            conditionMet = (m_lastExitCode >= reqLevel);

            size_t thenPos = rest.find(tokens[0]) + tokens[0].size();
            splitThenElse(rest.substr(thenPos), thenCmd, elseCmd);
        } else {
            // String comparison e.g. "a"=="b" or a EQU b
            conditionMet = parseStringComparison(rest, ignoreCase, thenCmd, elseCmd);
        }

        if (notFlag) conditionMet = !conditionMet;

        if (conditionMet) {
            if (!thenCmd.empty()) {
                return executeCompound(thenCmd, in, out, err);
            }
        } else {
            if (!elseCmd.empty()) {
                return executeCompound(elseCmd, in, out, err);
            }
        }
        return m_lastExitCode;
    }

    bool parseStringComparison(
        std::string_view rest,
        bool ignoreCase,
        std::string& outThen,
        std::string& outElse
    ) {
        size_t eqPos = rest.find("==");
        if (eqPos != std::string_view::npos) {
            std::string left = stripQuotes(trim(rest.substr(0, eqPos)));
            std::string rightAndTail = trim(rest.substr(eqPos + 2));

            // Extract right token
            std::string right;
            size_t rightEnd = 0;
            if (rightAndTail.front() == '"') {
                size_t nextQ = rightAndTail.find('"', 1);
                if (nextQ != std::string::npos) {
                    right = rightAndTail.substr(1, nextQ - 1);
                    rightEnd = nextQ + 1;
                }
            } else {
                size_t sp = rightAndTail.find_first_of(" \t");
                right = (sp == std::string::npos) ? rightAndTail : rightAndTail.substr(0, sp);
                rightEnd = (sp == std::string::npos) ? rightAndTail.size() : sp;
            }

            splitThenElse(rightAndTail.substr(rightEnd), outThen, outElse);
            return ignoreCase ? iequals(left, right) : (left == right);
        }
        return false;
    }

    static void splitThenElse(std::string_view tail, std::string& outThen, std::string& outElse) {
        std::string s = trim(tail);
        // Check for parenthesized block or ELSE
        size_t elsePos = std::string::npos;
        int depth = 0;
        bool inQ = false;

        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '"') inQ = !inQ;
            if (!inQ) {
                if (s[i] == '(') depth++;
                else if (s[i] == ')') depth = std::max(0, depth - 1);
                else if (depth == 0 && i + 4 <= s.size() && iequals(s.substr(i, 4), "else")) {
                    // Check word boundary
                    bool leftOk = (i == 0 || std::isspace(static_cast<unsigned char>(s[i - 1])) || s[i - 1] == ')');
                    bool rightOk = (i + 4 == s.size() || std::isspace(static_cast<unsigned char>(s[i + 4])) || s[i + 4] == '(');
                    if (leftOk && rightOk) {
                        elsePos = i;
                        break;
                    }
                }
            }
        }

        if (elsePos != std::string::npos) {
            outThen = trim(s.substr(0, elsePos));
            outElse = trim(s.substr(elsePos + 4));
        } else {
            outThen = s;
            outElse = "";
        }
    }

    int cmdFor(
        std::string_view fullLine,
        std::istream& in,
        std::ostream& out,
        std::ostream& err
    ) {
        std::string s = trim(fullLine);
        if (!iequals(s.substr(0, 4), "for ") && !iequals(s.substr(0, 4), "for\t")) return 1;
        std::string rest = trim(s.substr(4));

        bool numericLoop = false;
        if (iequals(rest.substr(0, 3), "/l ") || iequals(rest.substr(0, 3), "/l\t")) {
            numericLoop = true;
            rest = trim(rest.substr(3));
        }

        // Variable name e.g. %i or %%i
        size_t pctPos = rest.find('%');
        if (pctPos == std::string::npos) return 1;
        size_t varStart = pctPos;
        while (varStart < rest.size() && rest[varStart] == '%') varStart++;
        if (varStart >= rest.size()) return 1;
        char varName = rest[varStart];
        std::string varPlaceholder = std::string("%") + varName;
        std::string varPlaceholderDouble = std::string("%%") + varName;

        size_t inPos = std::string::npos;
        for (size_t i = varStart + 1; i + 2 <= rest.size(); ++i) {
            if (iequals(rest.substr(i, 2), "in") &&
                (i == 0 || std::isspace(static_cast<unsigned char>(rest[i - 1]))) &&
                (i + 2 == rest.size() || std::isspace(static_cast<unsigned char>(rest[i + 2])) || rest[i + 2] == '(')) {
                inPos = i;
                break;
            }
        }
        if (inPos == std::string::npos) return 1;

        size_t openParen = rest.find('(', inPos);
        if (openParen == std::string::npos) return 1;
        size_t closeParen = rest.find(')', openParen);
        if (closeParen == std::string::npos) return 1;

        std::string setContent = rest.substr(openParen + 1, closeParen - openParen - 1);
        std::string doTail = trim(rest.substr(closeParen + 1));
        std::string cmdTemplate;
        if (iequals(doTail.substr(0, 3), "do ") || iequals(doTail.substr(0, 3), "do\t")) {
            cmdTemplate = trim(doTail.substr(3));
        } else if (iequals(doTail.substr(0, 2), "do")) {
            cmdTemplate = trim(doTail.substr(2));
        } else {
            return 1;
        }

        if (numericLoop) {
            // FOR /L %i IN (start,step,end) DO command
            auto nums = CmdParser::splitTokens(replaceAll(setContent, ",", " "));
            if (nums.size() < 3) return 1;
            int64_t start = std::strtoll(nums[0].c_str(), nullptr, 0);
            int64_t step = std::strtoll(nums[1].c_str(), nullptr, 0);
            int64_t end = std::strtoll(nums[2].c_str(), nullptr, 0);
            if (step == 0) return 1;

            for (int64_t v = start; (step > 0 ? v <= end : v >= end); v += step) {
                std::string instCmd = replaceAll(cmdTemplate, varPlaceholderDouble, std::to_string(v));
                instCmd = replaceAll(instCmd, varPlaceholder, std::to_string(v));
                m_env.setVar(std::string(1, varName), std::to_string(v));
                executeCompound(instCmd, in, out, err);
            }
        } else {
            // FOR %i IN (items) DO command
            auto items = CmdParser::splitTokens(setContent);
            for (const auto& item : items) {
                std::string val = stripQuotes(item);
                std::string instCmd = replaceAll(cmdTemplate, varPlaceholderDouble, val);
                instCmd = replaceAll(instCmd, varPlaceholder, val);
                m_env.setVar(std::string(1, varName), val);
                executeCompound(instCmd, in, out, err);
            }
        }
        return m_lastExitCode;
    }

    int cmdTitle(const std::vector<std::string>& /*tokens*/, const std::string& fullLine) {
        size_t pos = fullLine.find_first_not_of(" \t", 5);
        std::string title = (pos != std::string::npos) ? fullLine.substr(pos) : "";
        std::wstring wTitle(title.begin(), title.end());
        win32::SetConsoleTitleW(wTitle.c_str());
        return 0;
    }

    int cmdColor(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() < 2) {
            win32::SetConsoleTextAttribute(win32::GetStdHandle(win32::STD_OUTPUT_HANDLE), 0x07);
            return 0;
        }
        uint16_t attr = static_cast<uint16_t>(std::strtoul(tokens[1].c_str(), nullptr, 16));
        win32::SetConsoleTextAttribute(win32::GetStdHandle(win32::STD_OUTPUT_HANDLE), attr);
        out << "Console color set to 0x" << std::hex << attr << std::dec << "\n";
        return 0;
    }

    int cmdPath(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() == 1) {
            std::string p;
            m_env.getVar("PATH", p, m_lastExitCode);
            out << "PATH=" << p << "\n";
            return 0;
        }
        m_env.setVar("PATH", tokens[1]);
        return 0;
    }

    int cmdPrompt(const std::vector<std::string>& /*tokens*/, const std::string& fullLine) {
        size_t pos = fullLine.find_first_not_of(" \t", 6);
        std::string p = (pos != std::string::npos) ? fullLine.substr(pos) : "$P$G";
        m_env.setVar("PROMPT", p);
        return 0;
    }

    int cmdVol(const std::vector<std::string>& /*tokens*/, std::ostream& out) {
        out << " Volume in drive C is MICANT_SYS\n";
        out << " Volume Serial Number is 1337-BEEF\n";
        return 0;
    }

    int cmdLabel(const std::vector<std::string>& /*tokens*/, std::ostream& out) {
        out << "Volume in drive C is MICANT_SYS\n";
        out << "Volume Serial Number is 1337-BEEF\n";
        return 0;
    }

    int cmdDate(const std::vector<std::string>& tokens, std::ostream& out) {
        std::string d;
        m_env.getVar("DATE", d, m_lastExitCode);
        if (tokens.size() > 1 && iequals(tokens[1], "/t")) {
            out << d << "\n";
        } else {
            out << "System Date: " << d << "\n";
        }
        return 0;
    }

    int cmdTime(const std::vector<std::string>& tokens, std::ostream& out) {
        std::string t;
        m_env.getVar("TIME", t, m_lastExitCode);
        if (tokens.size() > 1 && iequals(tokens[1], "/t")) {
            out << t << "\n";
        } else {
            out << "System Time: " << t << "\n";
        }
        return 0;
    }

    int cmdTimeout(const std::vector<std::string>& tokens, std::ostream& out) {
        int seconds = 1;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/t") && i + 1 < tokens.size()) {
                seconds = static_cast<int>(std::strtol(tokens[++i].c_str(), nullptr, 10));
            } else if (std::isdigit(static_cast<unsigned char>(tokens[i][0]))) {
                seconds = static_cast<int>(std::strtol(tokens[i].c_str(), nullptr, 10));
            }
        }
        out << "Waiting for " << seconds << " seconds, press a key to continue ...\n";
        return 0;
    }

    int cmdChoice(const std::vector<std::string>& tokens, std::istream& in, std::ostream& out) {
        std::string choices = "YN";
        std::string message = "[Y,N]?";
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/c") && i + 1 < tokens.size()) {
                choices = toUpper(tokens[++i]);
            } else if (iequals(tokens[i], "/m") && i + 1 < tokens.size()) {
                message = tokens[++i];
            }
        }
        out << message << std::flush;
        std::string response;
        if (std::getline(in, response) && !response.empty()) {
            char choice = static_cast<char>(std::toupper(static_cast<unsigned char>(response[0])));
            size_t idx = choices.find(choice);
            if (idx != std::string::npos) {
                m_lastExitCode = static_cast<int>(idx + 1);
                return m_lastExitCode;
            }
        }
        m_lastExitCode = 1;
        return 1;
    }

    int cmdTasklist(std::ostream& out) {
        out << "\nImage Name                     PID Session Name        Session#    Mem Usage\n"
            << "========================= ======== ================ =========== ============\n"
            << "System                           4 Services                   0       256 K\n"
            << "smss.exe                       248 Services                   0       480 K\n"
            << "csrss.exe                      380 Console                    1     1,824 K\n"
            << "wininit.exe                    460 Services                   0       920 K\n"
            << "services.exe                   540 Services                   0     3,120 K\n"
            << "lsass.exe                      568 Services                   0     4,850 K\n"
            << "svchost.exe                    712 Services                   0    12,400 K\n"
            << "winlogon.exe                   820 Console                    1     2,450 K\n"
            << "conhost.exe                    944 Console                    1     3,280 K\n"
            << "cmd.exe                       1024 Console                    1     4,096 K\n\n";
        return 0;
    }

    int cmdTaskkill(const std::vector<std::string>& tokens, std::ostream& out) {
        std::string im;
        uint32_t pid = 0;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/im") && i + 1 < tokens.size()) im = tokens[++i];
            else if (iequals(tokens[i], "/pid") && i + 1 < tokens.size()) pid = static_cast<uint32_t>(std::strtoul(tokens[++i].c_str(), nullptr, 10));
        }
        if (!im.empty()) {
            out << "SUCCESS: The process \"" << im << "\" has been terminated.\n";
            return 0;
        } else if (pid > 0) {
            out << "SUCCESS: The process with PID " << pid << " has been terminated.\n";
            return 0;
        }
        out << "ERROR: Invalid syntax. Specify /im or /pid.\n";
        return 1;
    }

    int cmdStart(const std::vector<std::string>& tokens, const std::string& fullLine, std::ostream& out) {
        (void)fullLine;
        std::string prog;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (!tokens[i].starts_with("/")) {
                prog = tokens[i];
                break;
            }
        }
        if (prog.empty()) {
            out << "The system cannot find the file specified.\n";
            return 1;
        }
        out << "[CmdProcessor] Started background process: " << prog << "\n";
        return 0;
    }

    int cmdAssoc(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() == 1) {
            for (const auto& [ext, typ] : m_associations) {
                out << ext << "=" << typ << "\n";
            }
            return 0;
        }
        size_t eq = tokens[1].find('=');
        if (eq == std::string::npos) {
            auto it = m_associations.find(toLower(tokens[1]));
            if (it != m_associations.end()) {
                out << it->first << "=" << it->second << "\n";
            } else {
                out << "File association not found for extension " << tokens[1] << "\n";
                return 1;
            }
        } else {
            std::string ext = toLower(tokens[1].substr(0, eq));
            std::string typ = tokens[1].substr(eq + 1);
            m_associations[ext] = typ;
        }
        return 0;
    }

    int cmdFtype(const std::vector<std::string>& tokens, std::ostream& out) {
        if (tokens.size() == 1) {
            for (const auto& [typ, cmd] : m_fileTypes) {
                out << typ << "=" << cmd << "\n";
            }
            return 0;
        }
        size_t eq = tokens[1].find('=');
        if (eq == std::string::npos) {
            auto it = m_fileTypes.find(tokens[1]);
            if (it != m_fileTypes.end()) {
                out << it->first << "=" << it->second << "\n";
            } else {
                out << "File type '" << tokens[1] << "' not found or no open command associated with it.\n";
                return 1;
            }
        } else {
            std::string typ = tokens[1].substr(0, eq);
            std::string cmd = tokens[1].substr(eq + 1);
            m_fileTypes[typ] = cmd;
        }
        return 0;
    }

    int handleCmdExeInvocation(
        std::string_view line,
        std::istream& in,
        std::ostream& out,
        std::ostream& err
    ) {
        auto tokens = CmdParser::splitTokens(line);
        if (tokens.size() <= 1) {
            // Interactive cmd prompt
            return 0;
        }

        std::string subCmd;
        bool exitAfter = false;
        (void)exitAfter;

        for (size_t i = 1; i < tokens.size(); ++i) {
            if (iequals(tokens[i], "/c")) {
                exitAfter = true;
                // Join remaining tokens into command string
                size_t cPos = line.find(tokens[i]) + tokens[i].size();
                subCmd = trim(line.substr(cPos));
                break;
            } else if (iequals(tokens[i], "/k")) {
                exitAfter = false;
                size_t kPos = line.find(tokens[i]) + tokens[i].size();
                subCmd = trim(line.substr(kPos));
                break;
            } else if (iequals(tokens[i], "/v:on")) {
                m_env.setDelayedExpansion(true);
            } else if (iequals(tokens[i], "/v:off")) {
                m_env.setDelayedExpansion(false);
            } else if (iequals(tokens[i], "/q")) {
                // Echo off
            }
        }

        if (!subCmd.empty()) {
            subCmd = stripQuotes(subCmd);
            int rc = executeCompound(subCmd, in, out, err);
            return rc;
        }
        return 0;
    }

    // ========================================================================
    // Helpers & File System Utilities
    // ========================================================================

    void initializeAssociations() {
        m_associations[".bat"] = "batfile";
        m_associations[".cmd"] = "cmdfile";
        m_associations[".exe"] = "exefile";
        m_associations[".txt"] = "txtfile";

        m_fileTypes["batfile"] = "\"%1\" %*";
        m_fileTypes["cmdfile"] = "\"%1\" %*";
        m_fileTypes["exefile"] = "\"%1\" %*";
        m_fileTypes["txtfile"] = "notepad.exe \"%1\"";
    }

    void registerSystemCmdBinary() {
        // Register cmd.exe in VirtualFileSystem and DynamicLoader
        auto& vfs = fs::VirtualFileSystem::get();
        vfs.initialize();
        std::shared_ptr<fs::FileObject> fObj;
        vfs.createOrOpenFile(L"C:\\Windows\\System32\\cmd.exe", fs::FILE_GENERIC_READ | fs::FILE_GENERIC_WRITE, fs::FILE_OPEN_IF, fObj);

        ldr::DynamicLoader::get().registerExport("cmd.exe", "main", reinterpret_cast<void*>(+[]() -> int {
            return 0;
        }));
        ldr::DynamicLoader::get().registerExport("cmd.exe", "wmain", reinterpret_cast<void*>(+[]() -> int {
            return 0;
        }));
    }

public:
    bool vfsFileExists(const std::string& path) const {
        std::wstring w(path.begin(), path.end());
        uint32_t attrs = 0;
        return NT_SUCCESS(fs::VirtualFileSystem::get().queryFileAttributes(w, attrs));
    }

    std::string readVfsTextFile(const std::string& path) const {
        std::wstring w(path.begin(), path.end());
        std::shared_ptr<fs::FileObject> fObj;
        NtStatus st = fs::VirtualFileSystem::get().createOrOpenFile(w, fs::FILE_GENERIC_READ, fs::FILE_OPEN, fObj);
        if (!NT_SUCCESS(st) || !fObj) return "";
        const auto& data = fObj->getData();
        return std::string(data.begin(), data.end());
    }

    void writeVfsTextFile(const std::string& path, const std::string& content, bool append) {
        std::wstring w(path.begin(), path.end());
        std::shared_ptr<fs::FileObject> fObj;
        uint32_t disp = append ? fs::FILE_OPEN_IF : fs::FILE_OVERWRITE_IF;
        NtStatus st = fs::VirtualFileSystem::get().createOrOpenFile(w, fs::FILE_GENERIC_WRITE, disp, fObj);
        if (!NT_SUCCESS(st) || !fObj) return;

        LargeInteger offset{};
        if (append) {
            offset.quadPart = static_cast<int64_t>(fObj->getFileSize());
        }
        uint32_t written = 0;
        fs::VirtualFileSystem::get().writeFile(fObj.get(), content.data(), static_cast<uint32_t>(content.size()), append ? &offset : nullptr, written);
        fs::VirtualFileSystem::get().closeFile(fObj.get());
    }

    std::string resolveExecutablePath(const std::string& name) const {
        if (vfsFileExists(name)) return name;
        if (!name.ends_with(".bat") && vfsFileExists(name + ".bat")) return name + ".bat";
        if (!name.ends_with(".cmd") && vfsFileExists(name + ".cmd")) return name + ".cmd";
        if (!name.ends_with(".exe") && vfsFileExists(name + ".exe")) return name + ".exe";

        // Check in current dir
        std::string cur = getCurrentDirectory() + "\\" + name;
        if (vfsFileExists(cur)) return cur;
        if (vfsFileExists(cur + ".bat")) return cur + ".bat";
        if (vfsFileExists(cur + ".cmd")) return cur + ".cmd";
        if (vfsFileExists(cur + ".exe")) return cur + ".exe";

        return name;
    }

    bool canRunBinary(const std::string& path) const {
        return vfsFileExists(path);
    }

    int runExternalBinary(const std::string& binaryPath, const std::vector<std::string>& /*args*/, std::ostream& out) {
        out << "[CMD] Executing: " << binaryPath << "\n";
        return 0;
    }

    static std::string substituteBatchParameters(
        std::string_view line,
        const std::string& scriptPath,
        const std::vector<std::string>& args
    ) {
        std::string out;
        out.reserve(line.size() * 2);

        // Compute metadata
        size_t slash = scriptPath.find_last_of("\\/");
        std::string dp0 = (slash == std::string::npos) ? ".\\" : scriptPath.substr(0, slash + 1);
        std::string nx0 = (slash == std::string::npos) ? scriptPath : scriptPath.substr(slash + 1);
        std::string f0 = scriptPath;

        for (size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '%' && i + 1 < line.size()) {
                // Check %~dp0
                if (i + 4 < line.size() && line.substr(i, 5) == "%~dp0") {
                    out += dp0;
                    i += 4;
                    continue;
                }
                // Check %~nx0
                if (i + 4 < line.size() && line.substr(i, 5) == "%~nx0") {
                    out += nx0;
                    i += 4;
                    continue;
                }
                // Check %~f0
                if (i + 3 < line.size() && line.substr(i, 4) == "%~f0") {
                    out += f0;
                    i += 3;
                    continue;
                }
                // Check %~1
                if (i + 2 < line.size() && line.substr(i, 3) == "%~1") {
                    if (!args.empty()) out += stripQuotes(args[0]);
                    i += 2;
                    continue;
                }
                // Check %*
                if (line[i + 1] == '*') {
                    std::string joined;
                    for (size_t a = 0; a < args.size(); ++a) {
                        if (a > 0) joined += " ";
                        joined += args[a];
                    }
                    out += joined;
                    i++;
                    continue;
                }
                // Check %0
                if (line[i + 1] == '0') {
                    out += scriptPath;
                    i++;
                    continue;
                }
                // Check %1..%9
                if (std::isdigit(static_cast<unsigned char>(line[i + 1]))) {
                    int argIdx = line[i + 1] - '1';
                    if (argIdx >= 0 && static_cast<size_t>(argIdx) < args.size()) {
                        out += args[static_cast<size_t>(argIdx)];
                    }
                    i++;
                    continue;
                }
            }
            out.push_back(line[i]);
        }
        return out;
    }

    static std::vector<std::string> splitLines(std::string_view text) {
        std::vector<std::string> lines;
        std::string current;
        for (char c : text) {
            if (c == '\r') continue;
            if (c == '\n') {
                lines.push_back(current);
                current.clear();
            } else {
                current.push_back(c);
            }
        }
        if (!current.empty()) lines.push_back(current);
        return lines;
    }

    static std::string replaceAll(std::string_view src, std::string_view oldSub, std::string_view newSub) {
        if (oldSub.empty()) return std::string(src);
        std::string res;
        size_t pos = 0;
        while (pos < src.size()) {
            size_t found = src.find(oldSub, pos);
            if (found == std::string_view::npos) {
                res.append(src.substr(pos));
                break;
            }
            res.append(src.substr(pos, found - pos));
            res.append(newSub);
            pos = found + oldSub.size();
        }
        return res;
    }

    void printHelp(std::ostream& out) {
        out << "For more information on a specific command, type HELP command-name\n"
            << "ASSOC          Displays or modifies file extension associations.\n"
            << "ATTRIB         Displays or changes file attributes.\n"
            << "CALL           Calls one batch program from another or subroutines.\n"
            << "CD             Displays the name of or changes the current directory.\n"
            << "CHOICE         Prompts the user to make a choice from a list of keys.\n"
            << "CLS            Clears the screen.\n"
            << "COLOR          Sets the default console foreground and background colors.\n"
            << "COPY           Copies one or more files to another location.\n"
            << "DATE           Displays or sets the date.\n"
            << "DEL            Deletes one or more files.\n"
            << "DIR            Displays a list of files and subdirectories in a directory.\n"
            << "ECHO           Displays messages, or turns command echoing on or off.\n"
            << "ENDLOCAL       Ends localization of environment changes in a batch file.\n"
            << "EXIT           Quits the CMD.EXE program (command interpreter).\n"
            << "FIND           Searches for a text string in a file or files.\n"
            << "FINDSTR        Searches for strings in files.\n"
            << "FOR            Runs a specified command for each file in a set of files.\n"
            << "FTYPE          Displays or modifies file types used in file extension associations.\n"
            << "GOTO           Directs the Windows command interpreter to a labeled line.\n"
            << "HELP           Provides Help information for Windows commands.\n"
            << "IF             Performs conditional processing in batch programs.\n"
            << "MD             Creates a directory.\n"
            << "MORE           Displays output one screen at a time.\n"
            << "MOVE           Moves one or more files from one directory to another directory.\n"
            << "PATH           Displays or sets a search path for executable files.\n"
            << "PAUSE          Suspends processing of a batch file and displays a message.\n"
            << "PROMPT         Changes the Windows command prompt.\n"
            << "RD             Removes a directory.\n"
            << "REM            Records comments (remarks) in batch files or CONFIG.SYS.\n"
            << "REN            Renames a file or files.\n"
            << "SET            Displays, sets, or removes Windows environment variables.\n"
            << "SETLOCAL       Begins localization of environment changes in a batch file.\n"
            << "SHIFT          Shifts the position of replaceable parameters in batch files.\n"
            << "SORT           Sorts input.\n"
            << "START          Starts a separate window to run a specified program or command.\n"
            << "TASKKILL       Terminate processes by process id or image name.\n"
            << "TASKLIST       Displays all currently running tasks including services.\n"
            << "TIME           Displays or sets the system time.\n"
            << "TIMEOUT        Pauses the command processor for the specified number of seconds.\n"
            << "TITLE          Sets the window title for a CMD.EXE window.\n"
            << "TREE           Graphically displays the directory structure of a drive or path.\n"
            << "TYPE           Displays the contents of a text file.\n"
            << "VER            Displays the Windows version.\n"
            << "VOL            Displays a disk volume label and serial number.\n"
            << "WHERE          Displays the locations of files that match the search pattern.\n"
            << "XCOPY          Copies files and directory trees.\n";
    }

    CmdEnvironment m_env;
    int m_lastExitCode{0};
    std::unordered_map<std::string, std::string> m_associations;
    std::unordered_map<std::string, std::string> m_fileTypes;
};

} // namespace micant::cmd
