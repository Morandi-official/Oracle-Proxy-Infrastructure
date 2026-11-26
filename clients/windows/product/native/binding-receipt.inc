// Included in the binding transaction after MaxReceiptChars and Fail are defined.
// The service is created by the elevated installer. Only this one registry
// value stores the original map across destruction of its software devnode.
static constexpr wchar_t bindingServiceKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\OracleProxyService";
static constexpr wchar_t bindingReceiptValue[] = L"OracleProxyOriginalWintunBindings";

static bool IsReceiptAdministrator(PSID sid) {
    return sid && IsValidSid(sid) &&
        (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
}

static void CheckReceiptKeySecurity(HKEY key) {
    constexpr SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD length = 0;
    if (RegGetKeySecurity(key, requested, nullptr, &length) != ERROR_INSUFFICIENT_BUFFER ||
        length == 0 || length > 64 * 1024) Fail("JOURNAL");
    std::vector<BYTE> bytes(length);
    auto descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data());
    if (RegGetKeySecurity(key, requested, descriptor, &length) != ERROR_SUCCESS ||
        !IsValidSecurityDescriptor(descriptor)) Fail("JOURNAL");
    BOOL defaulted = FALSE, present = FALSE;
    PSID owner = nullptr;
    PACL acl = nullptr;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !IsReceiptAdministrator(owner) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl || !IsValidAcl(acl))
        Fail("JOURNAL");

    constexpr ACCESS_MASK writeRights = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
        WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(acl, i, &raw)) Fail("JOURNAL");
        auto header = static_cast<const ACE_HEADER*>(raw);
        if ((header->AceFlags & INHERIT_ONLY_ACE) || header->AceType == ACCESS_DENIED_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE || header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
            header->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) Fail("JOURNAL");
        auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if ((ace->Mask & writeRights) && !IsReceiptAdministrator(&ace->SidStart)) Fail("JOURNAL");
    }
}

struct ProtectedBindingValue {
    HKEY key = nullptr;
    explicit ProtectedBindingValue(bool write) {
        REGSAM access = KEY_QUERY_VALUE | READ_CONTROL | KEY_WOW64_64KEY;
        if (write) access |= KEY_SET_VALUE;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, bindingServiceKey, 0, access, &key) != ERROR_SUCCESS)
            Fail("JOURNAL");
        try {
            CheckReceiptKeySecurity(key);
        } catch (...) {
            RegCloseKey(key);
            throw;
        }
    }
    ~ProtectedBindingValue() { RegCloseKey(key); }
    ProtectedBindingValue(const ProtectedBindingValue&) = delete;
    ProtectedBindingValue& operator=(const ProtectedBindingValue&) = delete;

    std::vector<wchar_t> read() const {
        DWORD type = 0, size = 0;
        auto status = RegQueryValueExW(key, bindingReceiptValue, nullptr, &type, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND) return {};
        if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || size < 2 * sizeof(wchar_t) ||
            size % sizeof(wchar_t) || size > MaxReceiptChars * sizeof(wchar_t)) Fail("JOURNAL");
        std::vector<wchar_t> data(size / sizeof(wchar_t));
        const DWORD capacity = size;
        status = RegQueryValueExW(key, bindingReceiptValue, nullptr, &type,
            reinterpret_cast<BYTE*>(data.data()), &size);
        if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || size != capacity ||
            data.back() != 0 || data[data.size() - 2] != 0) Fail("JOURNAL");
        return data;
    }
};

static std::vector<wchar_t> ReadProtectedBindingReceipt() {
    return ProtectedBindingValue(false).read();
}

static void StoreProtectedBindingReceipt(const std::vector<wchar_t>& original) {
    ProtectedBindingValue value(true);
    const auto before = value.read();
    if (before == original && !original.empty()) {
        if (RegFlushKey(value.key) != ERROR_SUCCESS) Fail("JOURNAL");
        return;
    }
    if (!before.empty() || original.size() < 2 || original.size() > MaxReceiptChars) Fail("JOURNAL");
    if (RegSetValueExW(value.key, bindingReceiptValue, 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(original.data()), static_cast<DWORD>(original.size() * sizeof(wchar_t))) != ERROR_SUCCESS ||
        RegFlushKey(value.key) != ERROR_SUCCESS || value.read() != original) Fail("JOURNAL");
}

static void ClearProtectedBindingReceipt(const std::vector<wchar_t>& original) {
    ProtectedBindingValue value(true);
    const auto before = value.read();
    if (before.empty()) return;
    if (before != original || RegDeleteValueW(value.key, bindingReceiptValue) != ERROR_SUCCESS ||
        RegFlushKey(value.key) != ERROR_SUCCESS || !value.read().empty())
        Fail("JOURNAL");
}
