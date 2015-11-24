#ifndef __LIBJOSE_JWA_RSA_HPP__
#define __LIBJOSE_JWA_RSA_HPP__

#include "config.hpp"
#include <string>
#include "jose.hpp"
#include "jwa.hpp"

namespace JOSE {

class JWA_RSA {
public:
    JWA_RSA();
    explicit JWA_RSA(const std::string &);
    ~JWA_RSA();
    operator bool() const {return valid_;}
    std::string to_pem() const;
    std::string n() const;
    const ustring & n_raw() const;
    std::string e() const;
    const ustring & e_raw() const;
    std::string d() const;
    const ustring & d_raw() const;
    std::string p() const;
    const ustring & p_raw() const;
    std::string q() const;
    const ustring & q_raw() const;
    std::string dp() const;
    const ustring & dp_raw() const;
    std::string dq() const;
    const ustring & dq_raw() const;
    std::string qi() const;
    const ustring & qi_raw() const;
private:
    friend class JWA;
    JWA_RSA(void *);
    void init_();

    void *_;
    JOSE jose_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWA_RSA_HPP__
