#ifndef __LIBJOSE_JWK_HPP__
#define __LIBJOSE_JWK_HPP__

#include "config.hpp"
#include <string>
#include "exception.hpp"
#include "jwa.hpp"

namespace JOSE {

class JWK {
public:
    JWK(const std::string &json);
    JWK();
    ~JWK();
    operator bool() const {return valid_;}
    const std::string &use() const;
    const std::string &key_opts() const;
    const std::string &alg() const;
    const std::string &kid() const;
    const std::string &x5u() const;
    const std::string &x5t() const;
    const std::string &x5t_S256() const;
    const JWA &jwa() const {return jwa_;}
    JWA &jwa() {return jwa_;}
    std::string to_json() const;
    std::string to_pem() const {return jwa_.to_pem();}
private:
    void *_;
    JWA jwa_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWK_HPP__
