#include <libjose/jwa_rsa.hpp>
#include <libjose/jwa.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include "utility.hpp"

namespace JOSE {
namespace {

struct Key {
    enum Type {
            crv,
            x,
            y,
            d,
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
    {Key::crv, "crv"},
    {Key::x, "x"},
    {Key::y, "y"},
    {Key::d, "d"},
});

struct CurveImpl {
    typedef JWA_EC::Curve::Type Type;
    static const boost::bimap<Type, boost::bimaps::unordered_set_of<std::string>> lookup;
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

const boost::bimap<JWA_EC::Curve::Type, boost::bimaps::unordered_set_of<std::string>> CurveImpl::lookup = make_bimap<JWA_EC::Curve::Type, boost::bimaps::unordered_set_of<std::string>>({
    {JWA_EC::Curve::P256, "P-256"},
    {JWA_EC::Curve::P384, "P-384"},
    {JWA_EC::Curve::P521, "P-521"},
});

struct JWA_ECImpl {
    std::shared_ptr<rapidjson::Document> doc;
    JWA_EC::Curve::Type crv;
    ustring x, y, d;
    bool private_key;
    JWA_ECImpl(): doc{new rapidjson::Document} {}
    JWA_ECImpl(const std::string &json): doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JWA_ECImpl(void *_): doc{*reinterpret_cast<std::shared_ptr<rapidjson::Document>*>(_)} {}
    bool parse() {
        std::bitset<3> required;
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
                case Key::crv:
                    {
                        auto type = CurveImpl::key2type(i->value.GetString());
                        if (!type) {
                            return false;
                        }
                        required.set(0);
                        crv = *type;
                    }
                    break;
                case Key::x:
                    required.set(1);
                    x = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::y:
                    required.set(2);
                    y = urlsafe_base64_decode(i->value.GetString());
                    break;
                case Key::d:
                    private_key = true;
                    d = urlsafe_base64_decode(i->value.GetString());
                    break;
            }
        }
        return required.all();
    }
};

static inline const JWA_ECImpl *impl(const void * _) {
    return reinterpret_cast<const JWA_ECImpl*>(_);
}

static inline JWA_ECImpl *impl(void * _) {
    return reinterpret_cast<JWA_ECImpl*>(_);
}

} // namespace

JWA_EC::JWA_EC(): _{new JWA_ECImpl}, valid_{false} {
}

JWA_EC::JWA_EC(const std::string &json): _{new JWA_ECImpl{json}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

JWA_EC::JWA_EC(void *_): _{new JWA_ECImpl{_}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

void JWA_EC::init_() {
    if (!jose_) {
        return;
    }
    valid_ = impl(_)->parse();
}

JWA_EC::~JWA_EC() {
    delete impl(_);
}

std::string JWA_EC::to_pem() const {
    if (impl(_)->private_key) {
        return ECPrivateKey2PEM(crv(), x_raw(), y_raw(), d_raw());
    } else {
        return ECPublicKey2PEM(crv(), x_raw(), y_raw());
    }
}

JWA_EC::Curve::Type JWA_EC::crv() const {
    return impl(_)->crv;
}

std::string JWA_EC::x() const {
    return urlsafe_base64_encode(x_raw());
}
const ustring & JWA_EC::x_raw() const {
    return impl(_)->x;
}

std::string JWA_EC::y() const {
    return urlsafe_base64_encode(y_raw());
}
const ustring & JWA_EC::y_raw() const {
    return impl(_)->y;
}

std::string JWA_EC::d() const {
    return urlsafe_base64_encode(d_raw());
}
const ustring & JWA_EC::d_raw() const {
    return impl(_)->d;
}

} // namespace JOSE
