#ifndef __LIBJOSE_CONFIG_HPP__
#define __LIBJOSE_CONFIG_HPP__

#ifndef __cplusplus
#error this header is for C++.
#endif

#include <string>
typedef std::basic_string<unsigned char> ustring;
static inline ustring to_ustring(const std::string &str) {
    return ustring(str.begin(), str.end());
}
static inline std::string to_string(const ustring &str) {
    return std::string(str.begin(), str.end());
}

#endif // __LIBJOSE_CONFIG_HPP__
