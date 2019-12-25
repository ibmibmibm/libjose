#ifndef __LIBJOSE_JWA_HPP__
#define __LIBJOSE_JWA_HPP__

#include "config.hpp"
#include "jwa_ec.hpp"
#include <string>

namespace JOSE {

class JWA_OCT;
class JWA_RSA;
class JWA_EC;

class JWA {
  public:
    struct KeyType {
        enum Type {
            OCT,
            RSA,
            EC,
        };
    };
    struct JWEAlg {
        enum Type {
            RSA1_5,
            RSA_OAEP,
            RSA_OAEP_256,
            A128KW,
            A192KW,
            A256KW,
            DIRECT,
            ECDH_ES,
            ECDH_ES_A128KW,
            ECDH_ES_A192KW,
            ECDH_ES_A256KW,
            A128GCMKW,
            A192GCMKW,
            A256GCMKW,
            PBES2_HS256_A128KW,
            PBES2_HS384_A192KW,
            PBES2_HS512_A256KW,
        };
    };
    JWA();
    explicit JWA(const std::string &json);
    ~JWA();
    operator bool() const { return valid_; }
    std::string to_pem() const;
    const KeyType::Type &kty() const;
    JWA_OCT &oct() { return *jwaimpl_.oct; }
    const JWA_OCT &oct() const { return *jwaimpl_.oct; }
    JWA_RSA &rsa() { return *jwaimpl_.rsa; }
    const JWA_RSA &rsa() const { return *jwaimpl_.rsa; }
    JWA_EC &ec() { return *jwaimpl_.ec; }
    const JWA_EC &ec() const { return *jwaimpl_.ec; }

  private:
    friend class JWK;
    JWA(void *);
    void init_();

    void *_;
    union {
        JWA_OCT *oct;
        JWA_RSA *rsa;
        JWA_EC *ec;
    } jwaimpl_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWA_HPP__
