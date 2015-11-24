#include <libjose/jwa_oct.hpp>
#include <libjose/jwa.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include "utility.hpp"

namespace JOSE {
namespace {

struct Key {
    enum Type {
        k,
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
    {Key::k, "k"},
});

struct JWA_OCTImpl {
    std::shared_ptr<rapidjson::Document> doc;
    std::string k;
    JWA_OCTImpl(): doc{new rapidjson::Document} {}
    JWA_OCTImpl(const std::string &json): doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JWA_OCTImpl(void *_): doc{*reinterpret_cast<std::shared_ptr<rapidjson::Document>*>(_)} {}
    bool parse() {
        for (rapidjson::Value::ConstMemberIterator i = doc->MemberBegin(); i != doc->MemberEnd(); ++i) {
            auto key = Key::key2type(i->name.GetString());
            if (!key) {
                continue;
            }
            switch (*key) {
                case Key::k:
                    if (!i->value.IsString()) {
                        return false;
                    }
                    k = i->value.GetString();
                    break;
                default:
                    break;
            }
        }
        return true;
    }
};

static inline const JWA_OCTImpl *impl(const void * _) {
    return reinterpret_cast<const JWA_OCTImpl*>(_);
}

static inline JWA_OCTImpl *impl(void * _) {
    return reinterpret_cast<JWA_OCTImpl*>(_);
}

} // namespace

JWA_OCT::JWA_OCT(): _{new JWA_OCTImpl}, valid_{false} {
}

JWA_OCT::JWA_OCT(const std::string &json): _{new JWA_OCTImpl{json}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

JWA_OCT::JWA_OCT(void *_): _{new JWA_OCTImpl{_}}, jose_{&impl(_)->doc}, valid_{false}  {
    init_();
}

void JWA_OCT::init_() {
    if (!jose_) {
        return;
    }
    valid_ = impl(_)->parse();
}

JWA_OCT::~JWA_OCT() {
    delete impl(_);
}

const std::string & JWA_OCT::k() const {
    return impl(_)->k;
}

} // namespace JOSE
