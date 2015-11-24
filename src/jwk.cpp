#include <libjose/jwk.hpp>
#include <libjose/jwa.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include <rapidjson/writer.h>
#include "utility.hpp"

namespace JOSE {
namespace {

struct Key {
    enum Type {
        use,
        key_opts,
        alg,
        kid,
        x5u,
        x5t,
        x5t_S256,
    };
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

const boost::bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>> Key::lookup = make_bimap<Key::Type, boost::bimaps::unordered_set_of<std::string>>({
    {use, "use"},
    {key_opts, "key_opts"},
    {alg, "alg"},
    {kid, "kid"},
    {x5u, "x5u"},
    {x5t, "x5t"},
    {x5t_S256, "x5t#S256"},
});

struct JWKImpl {
    std::shared_ptr<rapidjson::Document> doc;
    std::string use, key_opts, alg, kid, x5u, x5t, x5t_S256;
    JWKImpl(): doc{new rapidjson::Document} {}
    JWKImpl(const std::string &json): doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JWKImpl(std::shared_ptr<rapidjson::Document> _): doc{_} {}
    bool parse() {
        for (auto i = doc->MemberBegin(); i != doc->MemberEnd(); ++i) {
            auto key = Key::key2type(i->name.GetString());
            if (!key) {
                continue;
            }
            switch (*key) {
                case Key::use:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    use = i->value.GetString();
                    break;
                case Key::key_opts:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    key_opts = i->value.GetString();
                    break;
                case Key::alg:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    alg = i->value.GetString();
                    break;
                case Key::kid:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    kid = i->value.GetString();
                    break;
                case Key::x5u:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    x5u = i->value.GetString();
                    break;
                case Key::x5t:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    x5t = i->value.GetString();
                    break;
                case Key::x5t_S256:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    x5t_S256 = i->value.GetString();
                    break;
            }
        }
        return true;
    }
};

static inline const JWKImpl *impl(const void * _) {
    return reinterpret_cast<const JWKImpl*>(_);
}

static inline JWKImpl *impl(void * _) {
    return reinterpret_cast<JWKImpl*>(_);
}

} // namespace

JWK::JWK(): _{new JWKImpl}, jwa_{_}, valid_{false} {
}

JWK::JWK(const std::string &json): _{new JWKImpl{json}}, jwa_{_}, valid_{false}  {
    if (!jwa_) {
        return;
    }
    valid_ = impl(_)->parse();
}

JWK::~JWK() {
    delete impl(_);
}

const std::string &JWK::kid() const {
    return impl(_)->kid;
}

std::string JWK::to_json() const {
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    impl(_)->doc->Accept(writer);
    return s.GetString();
}

} // namespace JOSE
