#if !defined(_MSC_VER) || !defined(_MSC_FULL_VER) || !defined(_MSC_BUILD)
#error QPERIAPT_MSVC_VERSION_MACROS_UNAVAILABLE
#endif
#if !defined(_M_X64) || defined(_M_ARM64EC) || defined(_M_ARM64) || \
    defined(_M_ARM) || defined(_M_IX86)
#error QPERIAPT_MSVC_X64_REQUIRED
#endif
QPERIAPT_MSVC_VERSION _MSC_VER _MSC_FULL_VER _MSC_BUILD _M_X64
