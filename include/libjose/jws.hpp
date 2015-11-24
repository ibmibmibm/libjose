#ifndef __LIBJOSE_JWS_HPP__
#define __LIBJOSE_JWS_HPP__

#include "config.hpp"
#include <string>
#include "exception.hpp"
#include "jwa.hpp"

namespace JOSE {

class JWK;
class JWS {
public:
    struct Alg {
        enum Type {
            HS256,
            HS384,
            HS512,
            RS256,
            RS384,
            RS512,
            ES256,
            ES384,
            ES512,
            PS256,
            PS384,
            PS512,
            NONE,
        };
    };
    JWS(const std::string &header, const std::string &payload, const std::string &signature);
    JWS();
    ~JWS();
    operator bool() const {return valid_;}
    bool verify(const JWK &jwk) const;
    std::string header() const;
    std::string payload() const;
    std::string signature() const;
    void set_alg(Alg::Type alg);
    void set_jwk(const JWK &jwk);
    void set_payload(const std::string &payload);
    bool sign(const JWK &jwk);
    std::string to_string() const {return header() + '.' + payload() + '.' + signature();}
private:
    void *_;
    bool valid_;
};

} // namespace JOSE

#endif // __LIBJOSE_JWS_HPP__
