#ifndef __LIBJOSE_JWA_OCT_HPP__
#define __LIBJOSE_JWA_OCT_HPP__

#include "config.hpp"
#include <string>
#include "jose.hpp"
#include "jwa.hpp"

namespace JOSE {

class JWA_OCT {
public:
    JWA_OCT();
    explicit JWA_OCT(const std::string &);
    ~JWA_OCT();
    operator bool() const {return valid_;}
    std::string k() const;
    const ustring & k_raw() const;
private:
    friend class JWA;
    JWA_OCT(void *);
    void init_();

    void *_;
    JOSE jose_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWA_OCT_HPP__
