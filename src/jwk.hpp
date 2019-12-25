#ifndef __JWK_HPP__
#define __JWK_HPP__

#include <libjose/jwk.hpp>
#include <rapidjson/document.h>

namespace JOSE {

struct JWKInit {
    void operator()(JWK &_, const rapidjson::Value &json) {
        std::string kty;
        for (rapidjson::Value::ConstMemberIterator i = json.MemberBegin();
             i != json.MemberEnd(); ++i) {
            try {
                switch (JWK::Key::key2type(i->name.GetString())) {
                case JWK::Key::kty:
                    if (i->value.IsString()) {
                        kty = i->value.GetString();
                    }
                    break;
                default:
                    break;
                }
            } catch (std::invalid_argument &) {
            }
        }
        if (kty.empty()) {
            throw std::invalid_argument{"not a valid JWK"};
        }
        _.jwa_ = JWANew(kty, json);
        if (!_.jwa_) {
            throw std::invalid_argument{"not a valid JWA"};
        }
    };

} // namespace JOSE

#endif // __JWK_HPP__
