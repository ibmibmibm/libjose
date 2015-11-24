#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include "utility.hpp"

namespace JOSE {
namespace {

static inline const EVP_MD *HashFunc2EVP(HashFunc::Type hash) {
    switch (hash) {
        case HashFunc::SHA256: return EVP_sha256();
        case HashFunc::SHA384: return EVP_sha384();
        case HashFunc::SHA512: return EVP_sha512();
    }
    return nullptr;
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

struct rsa {
    RSA *_;
    rsa(): _(RSA_new()) {}
    ~rsa() {RSA_free(_);}
    void set_n(const ustring &b) {
        _->n = BN_bin2bn(b.data(), b.size(), _->n);
    }
    void set_e(const ustring &b) {
        _->e = BN_bin2bn(b.data(), b.size(), _->e);
    }
    void set_d(const ustring &b) {
        _->d = BN_bin2bn(b.data(), b.size(), _->d);
    }
    void set_p(const ustring &b) {
        _->p = BN_bin2bn(b.data(), b.size(), _->p);
    }
    void set_q(const ustring &b) {
        _->q = BN_bin2bn(b.data(), b.size(), _->q);
    }
    void set_dp(const ustring &b) {
        _->dmp1 = BN_bin2bn(b.data(), b.size(), _->dmp1);
    }
    void set_dq(const ustring &b) {
        _->dmq1 = BN_bin2bn(b.data(), b.size(), _->dmq1);
    }
    void set_qi(const ustring &b) {
        _->iqmp = BN_bin2bn(b.data(), b.size(), _->iqmp);
    }
    operator RSA*() {return _;}
};

struct evp_pkey {
    EVP_PKEY *_;
    evp_pkey(): _(EVP_PKEY_new()) {}
    evp_pkey(int type, const ustring &key): _(EVP_PKEY_new_mac_key(type, nullptr, key.c_str(), key.size())) {}
    ~evp_pkey() {EVP_PKEY_free(_);}
    bool set(rsa &rsa) {
        return 1 == EVP_PKEY_set1_RSA(_, rsa);
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

extern "C" void __sanitizer_print_stack_trace(void);
void dump_backtrace() {
    __sanitizer_print_stack_trace();
}

} // namespace JOSE
