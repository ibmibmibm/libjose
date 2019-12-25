#include "utility.hpp"
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional.hpp>
#include <libjose/jose.hpp>

namespace JOSE {

struct JOSEImpl {
    std::shared_ptr<rapidjson::Document> doc;
    std::string k;
    JOSEImpl() : doc{new rapidjson::Document} {}
    JOSEImpl(const std::string &json) : doc{new rapidjson::Document} {
        doc->Parse(json.c_str());
    }
    JOSEImpl(void *_)
        : doc{*reinterpret_cast<std::shared_ptr<rapidjson::Document> *>(_)} {}
    bool parse() { return doc->IsObject(); }
};

static inline const JOSEImpl *impl(const void *_) {
    return reinterpret_cast<const JOSEImpl *>(_);
}

static inline JOSEImpl *impl(void *_) {
    return reinterpret_cast<JOSEImpl *>(_);
}

JOSE::JOSE() : _{new JOSEImpl}, valid_{impl(_)->parse()} {}

JOSE::JOSE(const std::string &json)
    : _{new JOSEImpl{json}}, valid_{impl(_)->parse()} {}

JOSE::JOSE(void *_) : _{new JOSEImpl{_}}, valid_{impl(_)->parse()} {}

JOSE::~JOSE() { delete impl(_); }

} // namespace JOSE
