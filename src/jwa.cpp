#include "utility.hpp"
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include <libjose/jwa.hpp>
#include <libjose/jwa_ec.hpp>
#include <libjose/jwa_oct.hpp>
#include <libjose/jwa_rsa.hpp>

namespace JOSE {
namespace {

struct Key {
    enum Type {
        kty,
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
            {Key::kty, "kty"},
        });

struct KeyType {
    typedef JWA::KeyType::Type Type;
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

const boost::bimap<JWA::KeyType::Type,
                   boost::bimaps::unordered_set_of<std::string>>
    KeyType::lookup = make_bimap<JWA::KeyType::Type,
                                 boost::bimaps::unordered_set_of<std::string>>({
        {JWA::KeyType::OCT, "oct"},
        {JWA::KeyType::RSA, "RSA"},
        {JWA::KeyType::EC, "EC"},
    });

struct JWAImpl {
    std::shared_ptr<rapidjson::Document> doc;
    JWA::KeyType::Type kty;
    JWAImpl() : doc{new rapidjson::Document} {}
    JWAImpl(const std::string &json) : doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JWAImpl(void *_)
        : doc{*reinterpret_cast<std::shared_ptr<rapidjson::Document> *>(_)} {}
    bool parse() {
        for (auto i = doc->MemberBegin(); i != doc->MemberEnd(); ++i) {
            auto key = Key::key2type(i->name.GetString());
            if (!key) {
                continue;
            }
            switch (*key) {
            case Key::kty:
                if (!i->value.IsString()) {
                    return false;
                }
                auto keytype = KeyType::key2type(i->value.GetString());
                if (!keytype) {
                    return false;
                }
                kty = *keytype;
                switch (*keytype) {
                case JWA::KeyType::OCT:
                    break;
                case JWA::KeyType::RSA:
                    break;
                case JWA::KeyType::EC:
                    break;
                }
                break;
            }
        }
        return true;
    }
};

static inline JWAImpl *impl(void *_) { return reinterpret_cast<JWAImpl *>(_); }

static inline const JWAImpl *impl(const void *_) {
    return reinterpret_cast<const JWAImpl *>(_);
}

} // namespace

JWA::JWA() : _{new JWAImpl}, valid_{false} {}

JWA::JWA(const std::string &json) : _{new JWAImpl{json}}, valid_{false} {
    init_();
}

JWA::JWA(void *_) : _{new JWAImpl{_}}, valid_{false} { init_(); }

void JWA::init_() {
    valid_ = impl(_)->parse();
    if (!valid_) {
        return;
    }
    switch (impl(_)->kty) {
    case JWA::KeyType::OCT:
        jwaimpl_.oct = new JWA_OCT(&impl(_)->doc);
        break;
    case JWA::KeyType::RSA:
        jwaimpl_.rsa = new JWA_RSA(&impl(_)->doc);
        break;
    case JWA::KeyType::EC:
        jwaimpl_.ec = new JWA_EC(&impl(_)->doc);
        break;
    }
}

JWA::~JWA() {
    if (valid_) {
        switch (impl(_)->kty) {
        case JWA::KeyType::OCT:
            delete jwaimpl_.oct;
            break;
        case JWA::KeyType::RSA:
            delete jwaimpl_.rsa;
            break;
        case JWA::KeyType::EC:
            delete jwaimpl_.ec;
            break;
        }
    }
    delete impl(_);
}

std::string JWA::to_pem() const {
    switch (kty()) {
    case KeyType::RSA:
        return rsa().to_pem();
    case KeyType::EC:
        return ec().to_pem();
    default:
        return std::string{};
    }
}

const KeyType::Type &JWA::kty() const { return impl(_)->kty; }

} // namespace JOSE
