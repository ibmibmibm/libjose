#ifndef __LIBJOSE_JWA_EC_HPP__
#define __LIBJOSE_JWA_EC_HPP__

#include "config.hpp"
#include "jose.hpp"
#include "jwa.hpp"
#include <string>

namespace JOSE {

class JWA_EC {
  public:
    struct Curve {
        enum Type {
            P256,
            P384,
            P521,
        };
    };
    JWA_EC();
    explicit JWA_EC(const std::string &);
    ~JWA_EC();
    operator bool() const { return valid_; }
    std::string to_pem() const;
    Curve::Type crv() const;
    std::string x() const;
    const ustring &x_raw() const;
    std::string y() const;
    const ustring &y_raw() const;
    std::string d() const;
    const ustring &d_raw() const;

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
