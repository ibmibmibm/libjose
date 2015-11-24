#include <bitset>
#include <libjose/jwa_rsa.hpp>
#include <libjose/jwa.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include "utility.hpp"

namespace JOSE {
namespace {

struct Key {
    enum Type {
        n,
        e,
        d,
        p,
        q,
        dp,
        dq,
        qi,
        oth,
        r,
        t,
    };
    static const boost::bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>> lookup;
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

const boost::bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>> Key::lookup = make_bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>>({
    {Key::n, "n"},
    {Key::e, "e"},
    {Key::d, "d"},
    {Key::p, "p"},
    {Key::q, "q"},
    {Key::dp, "dp"},
    {Key::dq, "dq"},
    {Key::qi, "qi"},
    {Key::oth, "oth"},
    {Key::r, "r"},
    {Key::t, "t"},
});

struct JWA_RSAImpl {
    std::shared_ptr<rapidjson::Document> doc;
    ustring n, e, d, p, q, dp, dq, qi, oth, r, t;
    bool private_key;
    JWA_RSAImpl(): doc{new rapidjson::Document} {}
    JWA_RSAImpl(const std::string &json): doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JWA_RSAImpl(void *_): doc{*reinterpret_cast<std::shared_ptr<rapidjson::Document>*>(_)} {}
    bool parse() {
        std::bitset<2> required;
        private_key = false;
        for (rapidjson::Value::ConstMemberIterator i = doc->MemberBegin(); i != doc->MemberEnd(); ++i) {
            auto key = Key::key2type(i->name.GetString());
            if (!key) {
                continue;
            }
            if (!i->value.IsString()) {
                return false;
            }
            switch (*key) {
                case Key::n:
                    required.set(0);
                    n = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::e:
                    required.set(1);
                    e = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::d:
                    private_key = true;
                    d = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::p:
                    p = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::q:
                    q = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::dp:
                    dp = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::dq:
                    dq = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::qi:
                    qi = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::oth:
                    oth = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::r:
                    r = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::t:
                    t = urlsafe_base64_decode(i->value.GetString());
                    break;
            }
        }
        return required.all();
    }
};

static inline const JWA_RSAImpl *impl(const void * _) {
    return reinterpret_cast<const JWA_RSAImpl*>(_);
}

static inline JWA_RSAImpl *impl(void * _) {
    return reinterpret_cast<JWA_RSAImpl*>(_);
}

} // namespace

JWA_RSA::JWA_RSA(): _{new JWA_RSAImpl}, valid_{false} {
}

JWA_RSA::JWA_RSA(const std::string &json): _{new JWA_RSAImpl{json}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

JWA_RSA::JWA_RSA(void *_): _{new JWA_RSAImpl{_}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

void JWA_RSA::init_() {
    if (!jose_) {
        return;
    }
    valid_ = impl(_)->parse();
}

JWA_RSA::~JWA_RSA() {
    delete impl(_);
}

std::string JWA_RSA::to_pem() const {
    if (impl(_)->private_key) {
        return RSAPrivateKey2PEM(n_raw(), e_raw(), d_raw(), p_raw(), q_raw(), dp_raw(), dq_raw(), qi_raw());
    } else {
        return RSAPublicKey2PEM(n_raw(), e_raw());
    }
}

std::string JWA_RSA::n() const {
    return urlsafe_base64_encode(n_raw());
}
const ustring & JWA_RSA::n_raw() const {
    return impl(_)->n;
}

std::string JWA_RSA::e() const {
    return urlsafe_base64_encode(e_raw());
}
const ustring & JWA_RSA::e_raw() const {
    return impl(_)->e;
}

std::string JWA_RSA::d() const {
    return urlsafe_base64_encode(d_raw());
}
const ustring & JWA_RSA::d_raw() const {
    return impl(_)->d;
}

std::string JWA_RSA::p() const {
    return urlsafe_base64_encode(p_raw());
}
const ustring & JWA_RSA::p_raw() const {
    return impl(_)->p;
}

std::string JWA_RSA::q() const {
    return urlsafe_base64_encode(q_raw());
}
const ustring & JWA_RSA::q_raw() const {
    return impl(_)->q;
}

std::string JWA_RSA::dp() const {
    return urlsafe_base64_encode(dp_raw());
}
const ustring & JWA_RSA::dp_raw() const {
    return impl(_)->dp;
}

std::string JWA_RSA::dq() const {
    return urlsafe_base64_encode(dq_raw());
}
const ustring & JWA_RSA::dq_raw() const {
    return impl(_)->dq;
}

std::string JWA_RSA::qi() const {
    return urlsafe_base64_encode(qi_raw());
}
const ustring & JWA_RSA::qi_raw() const {
    return impl(_)->qi;
}

} // namespace JOSE
