#ifndef __LIBJOSE_JOSE_HPP__
#define __LIBJOSE_JOSE_HPP__

#include "config.hpp"
#include <string>

namespace JOSE {

class JOSE {
public:
    JOSE();
    explicit JOSE(const std::string &json);
    ~JOSE();
    operator bool() const {return valid_;}
private:
    friend class JWA_OCT;
    friend class JWA_RSA;
    friend class JWA_EC;
    JOSE(void *);

    void *_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JOSE_HPP__
