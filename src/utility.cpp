#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <libjose/jwa_ec.hpp>
#include "utility.hpp"

namespace JOSE {
namespace {

static inline const EVP_MD *HashFunc2EVP(HashFunc::Type hash) {
    switch (hash) {
        case HashFunc::SHA256: return EVP_sha256();
        case HashFunc::SHA384: return EVP_sha384();
        case HashFunc::SHA512: return EVP_sha512();
        case HashFunc::NONE: return nullptr;
    }
}

static inline int CurveType2NID(JWA_EC::Curve::Type type) {
    switch (type) {
        case JWA_EC::Curve::P256: return NID_X9_62_prime256v1;
        case JWA_EC::Curve::P384: return NID_secp384r1;
        case JWA_EC::Curve::P521: return NID_secp521r1;
    }
}

template <HashFunc::Type> struct HashFuncTrait;
template<> struct HashFuncTrait<HashFunc::SHA256> { const EVP_MD *evp() {return EVP_sha256();} };
template<> struct HashFuncTrait<HashFunc::SHA384> { const EVP_MD *evp() {return EVP_sha384();} };
template<> struct HashFuncTrait<HashFunc::SHA512> { const EVP_MD *evp() {return EVP_sha512();} };

struct bio {
    BIO * _;
    bio(BIO * _):_(_) {}
    ~bio() {BIO_free(_);}
    operator BIO*() {
        return _;
    }
};

template <class String>
struct Sensitive: public String {
    Sensitive(): String{} {}
    template <typename T1> Sensitive(T1 &&a1): String(std::forward<T1>(a1)) {}
    template <typename T1, typename T2> Sensitive(T1 &&a1, T2 &&a2): String(std::forward<T1>(a1), std::forward<T2>(a2)) {}
    ~Sensitive() {
        OPENSSL_cleanse(&String::front(), String::size());
    };
};

static inline ustring bn2bin(const BIGNUM *x) {
    ustring buffer(BN_num_bytes(x), 0);
    const size_t len = BN_bn2bin(x, const_cast<unsigned char *>(buffer.data()));
    buffer.resize(len);
    return buffer;
}

static inline void bin2bn(BIGNUM *&x, const ustring &bin) {
    x = BN_bin2bn(bin.data(), bin.size(), x);
}

struct rsa {
    RSA *_;
    rsa(): _(RSA_new()) {}
    ~rsa() {RSA_free(_);}
    void set_n(const ustring &b) {
        bin2bn(_->n, b);
    }
    void set_e(const ustring &b) {
        bin2bn(_->e, b);
    }
    void set_d(const ustring &b) {
        bin2bn(_->d, b);
    }
    void set_p(const ustring &b) {
        bin2bn(_->p, b);
    }
    void set_q(const ustring &b) {
        bin2bn(_->q, b);
    }
    void set_dp(const ustring &b) {
        bin2bn(_->dmp1, b);
    }
    void set_dq(const ustring &b) {
        bin2bn(_->dmq1, b);
    }
    void set_qi(const ustring &b) {
        bin2bn(_->iqmp, b);
    }
    operator RSA*() {return _;}
};

struct ec {
    EC_KEY *_;
    ec(): _(EC_KEY_new()) {
        EC_KEY_set_asn1_flag(_, OPENSSL_EC_NAMED_CURVE);
    }
    ~ec() {EC_KEY_free(_);}
    void set_crv(JWA_EC::Curve::Type crv) {
        EC_GROUP *group = EC_GROUP_new_by_curve_name(CurveType2NID(crv));
        EC_KEY_set_group(_, group);
        EC_GROUP_free(group);
    }
    void set_xy(const ustring &x, const ustring &y) {
        BIGNUM *bx = nullptr;
        bin2bn(bx, x);
        BIGNUM *by = nullptr;
        bin2bn(by, y);
        EC_KEY_set_public_key_affine_coordinates(_, bx, by);
        BN_free(by);
        BN_free(bx);
    }
    void set_d(const ustring &d) {
        BIGNUM *bd = nullptr;
        bin2bn(bd, d);
        EC_KEY_set_private_key(_, bd);
        BN_free(bd);
    }
    operator EC_KEY*() {return _;}
};

struct evp_pkey {
    EVP_PKEY *_;
    evp_pkey(): _(EVP_PKEY_new()) {}
    evp_pkey(int type, const ustring &key): _(EVP_PKEY_new_mac_key(type, nullptr, key.c_str(), key.size())) {}
    ~evp_pkey() {EVP_PKEY_free(_);}
    bool set(rsa &rsa) {
        return 1 == EVP_PKEY_set1_RSA(_, rsa);
    }
    bool set(ec &ec) {
        return 1 == EVP_PKEY_set1_EC_KEY(_, ec);
    }
    operator EVP_PKEY*() {return _;}
};

template <class T1, class T2>
bool crypto_equal(const T1 &a1, const T2 &a2) {
    return 0 == CRYPTO_memcmp(a1.data(), a2.data(), std::min(a1.size(), a2.size()));
}

struct evp_md_ctx {
    EVP_MD_CTX *_;
    const EVP_MD *type;
    evp_md_ctx(const EVP_MD *type): _(EVP_MD_CTX_create()), type(type) {}
    ~evp_md_ctx() {EVP_MD_CTX_destroy(_);}
    bool init() {
        return EVP_DigestInit_ex(_, type, nullptr) == 1;
    }
    bool sign_init(evp_pkey &pkey) {
        return EVP_DigestSignInit(_, nullptr, type, nullptr, pkey) == 1;
    }
    bool sign_update(const void *d, unsigned int cnt) {return EVP_DigestSignUpdate(_, d, cnt) == 1;}
    Sensitive<ustring> sign_final() {
        size_t size = EVP_MAX_MD_SIZE;
        if (1 != EVP_DigestSignFinal(_, nullptr, &size)) {
            return Sensitive<ustring>{};
        }
        Sensitive<ustring> output(size, '\0');
        EVP_DigestSignFinal(_, &output[0], &size);
        output.resize(size);
        return output;
    }
    bool verify_init(evp_pkey &pkey) {return EVP_DigestVerifyInit(_, nullptr, type, nullptr, pkey) == 1;}
    bool verify_update(const void *d, unsigned int cnt) {return EVP_DigestVerifyUpdate(_, d, cnt) == 1;}
    bool verify_final(const ustring &sign) {
        return 1 == EVP_DigestVerifyFinal(_, sign.c_str(), sign.size());
    }
};

struct ecdsa_sig {
    ECDSA_SIG *_;
    ecdsa_sig(): _(ECDSA_SIG_new()) {}
    ~ecdsa_sig() {ECDSA_SIG_free(_);}
    BIGNUM *&r() {return _->r;}
    BIGNUM *&s() {return _->s;}
    operator ECDSA_SIG*() {return _;}
    operator ECDSA_SIG**() {return &_;}
};

static inline ustring signature_asn2jose(const ustring &asn) {
    ustring jose;
    ecdsa_sig sig;
    const unsigned char *p = asn.data();
    if (d2i_ECDSA_SIG(sig, &p, asn.size()) == nullptr) {
        return jose;
    }

    jose.append(bn2bin(sig.r()));
    jose.append(bn2bin(sig.s()));
    return jose;
}

static inline ustring signature_jose2asn(const ustring &jose) {
    ustring asan;
    ecdsa_sig sig;
    bin2bn(sig.r(), jose.substr(0, jose.size() / 2));
    bin2bn(sig.s(), jose.substr(jose.size() / 2));
    unsigned char *p = nullptr;
    int len;
    len = i2d_ECDSA_SIG(sig, &p);
    asan.append(p, len);
    if (p) OPENSSL_free(p);
    return asan;
}

static inline void urlsafe_encode(std::string &input) {
    for (char &c: input) {
        switch (c) {
            case '+': c = '-'; break;
            case '/': c = '_'; break;
            default: break;
        }
    }
}

static inline void urlsafe_decode(std::string &input) {
    for (char &c: input) {
        switch (c) {
            case '-': c = '+'; break;
            case '_': c = '/'; break;
            default: break;
        }
    }
}

} // namespace

std::string urlsafe_base64_encode(const ustring &input) {
    bio b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio mem(BIO_new(BIO_s_mem()));
    BIO_push(b64, mem);
    int ret;
    do {
        ret = BIO_write(b64, input.c_str(), input.size());
    } while (ret <= 0 && BIO_should_retry(b64));
    BIO_flush(b64);
    if (ret <= 0) {
        return std::string();
    }
    char *ptr;
    size_t len = BIO_get_mem_data(mem, &ptr);
    while (ptr[len - 1] == '=') {
        --len;
    }
    std::string result{ptr, len};
    urlsafe_encode(result);
    return result;
}

ustring urlsafe_base64_decode(const std::string &base64) {
    const size_t padding = (4 - base64.size() % 4) % 4;
    std::string input = base64 + std::string(padding, '=');
    urlsafe_decode(input);
    bio b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio mem(BIO_new_mem_buf(const_cast<char*>(input.c_str()), input.size()));
    BIO_push(b64, mem);
    int ret;
    ustring result;
    do {
        unsigned char buffer[4096];
        ret = BIO_read(b64, buffer, sizeof(buffer));
        if (ret > 0) {
            result.append(buffer, ret);
        }
    } while (ret > 0);
    if (ret != 0) {
        return ustring();
    }
    return result;
}

std::string RSAPublicKey2PEM(const ustring &n, const ustring &e) {
    rsa key;
    key.set_n(n);
    key.set_e(e);
    bio mem(BIO_new(BIO_s_mem()));
    if (1 != PEM_write_bio_RSA_PUBKEY(mem, key)) {
        return std::string{};
    }
    char *ptr;
    size_t len = BIO_get_mem_data(mem, &ptr);
    return std::string{ptr, len};
}

std::string RSAPrivateKey2PEM(const ustring &n, const ustring &e, const ustring &d, const ustring &p, const ustring &q, const ustring &dp, const ustring &dq, const ustring &qi) {
    rsa key;
    key.set_n(n);
    key.set_e(e);
    key.set_d(d);
    key.set_p(p);
    key.set_q(q);
    key.set_dp(dp);
    key.set_dq(dq);
    key.set_qi(qi);
    bio mem(BIO_new(BIO_s_mem()));
    if (1 != PEM_write_bio_RSAPrivateKey(mem, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        return std::string{};
    }
    char *ptr;
    size_t len = BIO_get_mem_data(mem, &ptr);
    return std::string{ptr, len};
}

std::string ECPublicKey2PEM(JWA_EC::Curve::Type crv, const ustring &x, const ustring &y) {
    ec key;
    key.set_crv(crv);
    key.set_xy(x, y);
    evp_pkey pkey;
    if (!pkey.set(key)) {
        return std::string{};
    }
    bio mem(BIO_new(BIO_s_mem()));
    if (1 != PEM_write_bio_PUBKEY(mem, pkey)) {
        return std::string{};
    }
    char *ptr;
    size_t len = BIO_get_mem_data(mem, &ptr);
    return std::string{ptr, len};
}

std::string ECPrivateKey2PEM(JWA_EC::Curve::Type crv, const ustring &x, const ustring &y, const ustring &d) {
    ec key;
    key.set_crv(crv);
    key.set_xy(x, y);
    key.set_d(d);
    bio mem(BIO_new(BIO_s_mem()));
    if (1 != PEM_write_bio_ECPrivateKey(mem, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        return std::string{};
    }
    char *ptr;
    size_t len = BIO_get_mem_data(mem, &ptr);
    return std::string{ptr, len};
}

ustring HMAC_sign(HashFunc::Type hash, const ustring &data, const ustring &key) {
    evp_pkey pkey{EVP_PKEY_HMAC, key};
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return ustring{};
    }
    if (!ctx.sign_init(pkey)) {
        return ustring{};
    }
    if (!ctx.sign_update(data.data(), data.size())) {
        return ustring{};
    }
    return ctx.sign_final();
}

bool HMAC_verify(HashFunc::Type hash, const ustring &data, const ustring &key, const ustring &signature) {
    evp_pkey pkey{EVP_PKEY_HMAC, key};
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return false;
    }
    if (!ctx.sign_init(pkey)) {
        return false;
    }
    if (!ctx.sign_update(data.data(), data.size())) {
        return false;
    }
    return crypto_equal(ctx.sign_final(), signature);
}

ustring RSA_sign(HashFunc::Type hash, const ustring &data, const ustring &n, const ustring &e, const ustring &d, const ustring &p, const ustring &q, const ustring &dp, const ustring &dq, const ustring &qi) {
    rsa key;
    key.set_n(n);
    key.set_e(e);
    key.set_d(d);
    key.set_p(p);
    key.set_q(q);
    key.set_dp(dp);
    key.set_dq(dq);
    key.set_qi(qi);
    evp_pkey pkey;
    if (!pkey.set(key)) {
        return ustring{};
    }
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return ustring{};
    }
    if (!ctx.sign_init(pkey)) {
        return ustring{};
    }
    if (!ctx.sign_update(data.data(), data.size())) {
        return ustring{};
    }
    return ctx.sign_final();
}

bool RSA_verify(HashFunc::Type hash, const ustring &data, const ustring &n, const ustring &e, const ustring &signature) {
    rsa key;
    key.set_n(n);
    key.set_e(e);
    evp_pkey pkey;
    if (!pkey.set(key)) {
        return false;
    }
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return false;
    }
    if (!ctx.verify_init(pkey)) {
        return false;
    }
    if (!ctx.verify_update(data.data(), data.size())) {
        return false;
    }
    return ctx.verify_final(signature);
}

ustring EC_sign(HashFunc::Type hash, const ustring &data, JWA_EC::Curve::Type crv, const ustring &x, const ustring &y, const ustring &d) {
    ec key;
    key.set_crv(crv);
    key.set_xy(x, y);
    key.set_d(d);
    evp_pkey pkey;
    if (!pkey.set(key)) {
        return ustring{};
    }
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return ustring{};
    }
    if (!ctx.sign_init(pkey)) {
        return ustring{};
    }
    if (!ctx.sign_update(data.data(), data.size())) {
        return ustring{};
    }
    return signature_asn2jose(ctx.sign_final());
}

bool EC_verify(HashFunc::Type hash, const ustring &data, JWA_EC::Curve::Type crv, const ustring &x, const ustring &y, const ustring &signature) {
    ec key;
    key.set_crv(crv);
    key.set_xy(x, y);
    evp_pkey pkey;
    if (!pkey.set(key)) {
        return false;
    }
    evp_md_ctx ctx{HashFunc2EVP(hash)};
    if (!ctx.init()) {
        return false;
    }
    if (!ctx.verify_init(pkey)) {
        return false;
    }
    if (!ctx.verify_update(data.data(), data.size())) {
        return false;
    }
    return ctx.verify_final(signature_jose2asn(signature));
}


extern "C" void __sanitizer_print_stack_trace(void);
void dump_backtrace() {
    __sanitizer_print_stack_trace();
}

} // namespace JOSE
