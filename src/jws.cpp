#include "utility.hpp"
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include <iostream>
#include <libjose/jwa_ec.hpp>
#include <libjose/jwa_oct.hpp>
#include <libjose/jwa_rsa.hpp>
#include <libjose/jwk.hpp>
#include <libjose/jws.hpp>
#include <rapidjson/writer.h>

namespace JOSE {
namespace {

struct Key {
    enum Type {
        alg,
        jku,
        jwk,
        kid,
        x5u,
        x5c,
        x5t,
        x5t_S256,
        typ,
        cty,
        crit,
    };
    static const boost::bimap<Type,
                              boost::bimaps::unordered_set_of<std::string>>
        lookup;

    static boost::optional<const std::string &> type2key(Type type) {
        auto i = lookup.left.find(type);
        if (i == lookup.left.end()) {
            return boost::none;
        }
        return i->second;
    }

    static boost::optional<Type> key2type(const std::string &key) {
        auto i = lookup.right.find(key);
        if (i == lookup.right.end()) {
            return boost::none;
        }
        return i->second;
    }
};

const boost::bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>>
    Key::lookup =
        make_bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>>({
            {alg, "alg"},
            {jku, "jku"},
            {jwk, "jwk"},
            {kid, "kid"},
            {x5u, "x5u"},
            {x5c, "x5c"},
            {x5t, "x5t"},
            {x5t_S256, "x5t#S256"},
            {typ, "typ"},
            {cty, "cty"},
            {crit, "crit"},
        });

struct AlgImpl {
    typedef JWS::Alg::Type Type;
    static const boost::bimap<Type,
                              boost::bimaps::unordered_set_of<std::string>>
        lookup;
    static boost::optional<const std::string &> type2key(Type type) {
        auto i = lookup.left.find(type);
        if (i == lookup.left.end()) {
            return boost::none;
        }
        return i->second;
    }
    static boost::optional<Type> key2type(const std::string &key) {
        auto i = lookup.right.find(key);
        if (i == lookup.right.end()) {
            return boost::none;
        }
        return i->second;
    }
};

const boost::bimap<JWS::Alg::Type, boost::bimaps::unordered_set_of<std::string>>
    AlgImpl::lookup = make_bimap<JWS::Alg::Type,
                                 boost::bimaps::unordered_set_of<std::string>>({
        {JWS::Alg::HS256, "HS256"},
        {JWS::Alg::HS384, "HS384"},
        {JWS::Alg::HS512, "HS512"},
        {JWS::Alg::RS256, "RS256"},
        {JWS::Alg::RS384, "RS384"},
        {JWS::Alg::RS512, "RS512"},
        {JWS::Alg::ES256, "ES256"},
        {JWS::Alg::ES384, "ES384"},
        {JWS::Alg::ES512, "ES512"},
        {JWS::Alg::PS256, "PS256"},
        {JWS::Alg::PS384, "PS384"},
        {JWS::Alg::PS512, "PS512"},
        {JWS::Alg::NONE, "none"},
    });

static inline bool is_compatibility(JWA::KeyType::Type kty,
                                    JWS::Alg::Type alg) {
    switch (kty) {
    default:
        return false;
    case JWA::KeyType::OCT:
        switch (alg) {
        default:
            return false;
        case JWS::Alg::HS256:
        case JWS::Alg::HS384:
        case JWS::Alg::HS512:
            return true;
        }
    case JWA::KeyType::RSA:
        switch (alg) {
        default:
            return false;
        case JWS::Alg::RS256:
        case JWS::Alg::RS384:
        case JWS::Alg::RS512:
            return true;
        }
    case JWA::KeyType::EC:
        switch (alg) {
        default:
            return false;
        case JWS::Alg::ES256:
        case JWS::Alg::ES384:
        case JWS::Alg::ES512:
            return true;
        }
    }
}

static inline HashFunc::Type get_hash(JWS::Alg::Type alg) {
    switch (alg) {
    case JWS::Alg::HS256:
    case JWS::Alg::RS256:
    case JWS::Alg::ES256:
        return HashFunc::SHA256;
    case JWS::Alg::HS384:
    case JWS::Alg::RS384:
    case JWS::Alg::ES384:
        return HashFunc::SHA384;
    case JWS::Alg::HS512:
    case JWS::Alg::RS512:
    case JWS::Alg::ES512:
        return HashFunc::SHA512;
    default:
        return HashFunc::NONE;
    }
}

struct JWSImpl {
    std::shared_ptr<rapidjson::Document> doc;
    JWS::Alg::Type alg;
    std::string jku, jwk, kid, x5u, x5c, x5t, x5t_S256, typ, cty;
    ustring header, payload, signature;
    std::vector<std::string> crit;
    JWSImpl() : doc{new rapidjson::Document{rapidjson::kObjectType}} {}
    JWSImpl(const std::string &header_base64, const std::string &payload_base64,
            const std::string &signature_base64)
        : doc{new rapidjson::Document}, header{urlsafe_base64_decode(
                                            header_base64)},
          payload{urlsafe_base64_decode(payload_base64)},
          signature{urlsafe_base64_decode(signature_base64)} {
        doc->Parse(reinterpret_cast<const char *>(header.c_str()));
    }
    std::string header_base64() const { return urlsafe_base64_encode(header); }
    std::string payload_base64() const {
        return urlsafe_base64_encode(payload);
    }
    std::string signature_base64() const {
        return urlsafe_base64_encode(signature);
    }
    JWSImpl(std::shared_ptr<rapidjson::Document> _) : doc{_} {}
    void sync_header() {
        typedef rapidjson::GenericStringBuffer<rapidjson::UTF8<unsigned char>>
            UStringBuffer;
        UStringBuffer s;
        rapidjson::Writer<UStringBuffer> writer(s);
        doc->Accept(writer);
        header = s.GetString();
    }
    bool parse() {
        for (auto i = doc->MemberBegin(); i != doc->MemberEnd(); ++i) {
            auto key = Key::key2type(i->name.GetString());
            if (!key) {
                continue;
            }
            if ((*key == Key::crit && !i->value.IsArray()) ||
                !i->value.IsString()) {
                return false;
            }
            switch (*key) {
            case Key::alg: {
                auto type = AlgImpl::key2type(i->value.GetString());
                if (!type) {
                    return false;
                }
                alg = *type;
            } break;
            case Key::jku:
                jku = i->value.GetString();
                break;
            case Key::jwk:
                jwk = i->value.GetString();
                break;
            case Key::kid:
                kid = i->value.GetString();
                break;
            case Key::x5u:
                x5u = i->value.GetString();
                break;
            case Key::x5c:
                x5c = i->value.GetString();
                break;
            case Key::x5t:
                x5t = i->value.GetString();
                break;
            case Key::x5t_S256:
                x5t_S256 = i->value.GetString();
                break;
            case Key::typ:
                typ = i->value.GetString();
                break;
            case Key::cty:
                cty = i->value.GetString();
                break;
            case Key::crit:
                for (auto j = i->value.Begin(); j != i->value.End(); ++j) {
                    if (!j->IsString()) {
                        return false;
                    }
                    std::string c = j->GetString();
                    auto crit_key = Key::key2type(c);
                    if (!key) {
                        return false;
                    }
                    crit.emplace_back(std::move(c));
                }
                break;
            }
        }
        return true;
    }
};

static inline const JWSImpl *impl(const void *_) {
    return reinterpret_cast<const JWSImpl *>(_);
}

static inline JWSImpl *impl(void *_) { return reinterpret_cast<JWSImpl *>(_); }

} // namespace

JWS::JWS() : _{new JWSImpl}, valid_{false} {}

JWS::JWS(const std::string &header, const std::string &payload,
         const std::string &signature)
    : _{new JWSImpl{header, payload, signature}}, valid_{false} {
    valid_ = impl(_)->parse();
}

JWS::~JWS() { delete impl(_); }

std::string JWS::header() const { return impl(_)->header_base64(); }

std::string JWS::payload() const { return impl(_)->payload_base64(); }

std::string JWS::signature() const { return impl(_)->signature_base64(); }

void JWS::set_alg(Alg::Type alg) {
    impl(_)->alg = alg;
    rapidjson::Document &header = *impl(_)->doc;
    rapidjson::Document::AllocatorType &allocator = header.GetAllocator();
    header.AddMember(
        rapidjson::Value(Key::type2key(Key::alg)->c_str(), allocator),
        rapidjson::Value(AlgImpl::type2key(alg)->c_str(), allocator),
        allocator);
    impl(_)->sync_header();
}

void JWS::set_jwk(const JWK &jwk) {
    rapidjson::Document &header = *impl(_)->doc;
    rapidjson::Document::AllocatorType &allocator = header.GetAllocator();
    header.AddMember(
        rapidjson::Value(Key::type2key(Key::jwk)->c_str(), allocator),
        rapidjson::Value(jwk.to_json().c_str(), allocator), allocator);
    impl(_)->sync_header();
}

void JWS::set_payload(const std::string &payload) {
    impl(_)->payload = to_ustring(payload);
}

bool JWS::sign(const JWK &jwk) {
    const JWA &jwa = jwk.jwa();
    JWS::Alg::Type alg = impl(_)->alg;
    if (!is_compatibility(jwa.kty(), alg)) {
        return false;
    }
    const ustring data =
        to_ustring(impl(_)->header_base64() + '.' + impl(_)->payload_base64());
    ustring &signature = impl(_)->signature;
    switch (jwa.kty()) {
    case JWA::KeyType::OCT: {
        const ustring &key = jwa.oct().k_raw();
        signature = HMAC_sign(get_hash(alg), data, key);
        return true;
    } break;
    case JWA::KeyType::RSA: {
        const ustring &n = jwa.rsa().n_raw();
        const ustring &e = jwa.rsa().e_raw();
        const ustring &d = jwa.rsa().d_raw();
        const ustring &p = jwa.rsa().p_raw();
        const ustring &q = jwa.rsa().q_raw();
        const ustring &dp = jwa.rsa().dp_raw();
        const ustring &dq = jwa.rsa().dq_raw();
        const ustring &qi = jwa.rsa().qi_raw();
        signature = RSA_sign(get_hash(alg), data, n, e, d, p, q, dp, dq, qi);
        return true;
    } break;
    case JWA::KeyType::EC: {
        JWA_EC::Curve::Type crv = jwa.ec().crv();
        const ustring &x = jwa.ec().x_raw();
        const ustring &y = jwa.ec().y_raw();
        const ustring &d = jwa.ec().d_raw();
        signature = EC_sign(get_hash(alg), data, crv, x, y, d);
        return true;
    } break;
    }
    return false;
}

bool JWS::verify(const JWK &jwk) const {
    const JWA &jwa = jwk.jwa();
    JWS::Alg::Type alg = impl(_)->alg;
    if (!is_compatibility(jwa.kty(), alg)) {
        return false;
    }
    const ustring data =
        to_ustring(impl(_)->header_base64() + '.' + impl(_)->payload_base64());
    const ustring &signature = impl(_)->signature;
    switch (jwa.kty()) {
    case JWA::KeyType::OCT: {
        const ustring &key = jwa.oct().k_raw();
        return HMAC_verify(get_hash(alg), data, key, signature);
    } break;
    case JWA::KeyType::RSA: {
        const ustring data = to_ustring(impl(_)->header_base64() + '.' +
                                        impl(_)->payload_base64());
        const ustring &signature = impl(_)->signature;
        const ustring &n = jwa.rsa().n_raw();
        const ustring &e = jwa.rsa().e_raw();
        return RSA_verify(get_hash(alg), data, n, e, signature);
    } break;
    case JWA::KeyType::EC: {
        const ustring data = to_ustring(impl(_)->header_base64() + '.' +
                                        impl(_)->payload_base64());
        const ustring &signature = impl(_)->signature;
        JWA_EC::Curve::Type crv = jwa.ec().crv();
        const ustring &n = jwa.ec().x_raw();
        const ustring &e = jwa.ec().y_raw();
        return EC_verify(get_hash(alg), data, crv, n, e, signature);
    } break;
    }
    return false;
}

} // namespace JOSE
