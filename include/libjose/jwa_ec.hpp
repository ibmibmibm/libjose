#ifndef __LIBJOSE_JWA_EC_HPP__
#define __LIBJOSE_JWA_EC_HPP__

#include "config.hpp"
#include <string>
#include "jose.hpp"
#include "jwa.hpp"

namespace JOSE {

class JWA_EC {
public:
    JWA_EC();
    explicit JWA_EC(const std::string &);
    ~JWA_EC();
    operator bool() const {return valid_;}
    std::string to_pem() const;
private:
    friend class JWA;
    JWA_EC(void *);
    void init_();

    void *_;
    JOSE jose_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWA_EC_HPP__
