#define BOOST_TEST_MODULE jwk
#include <iostream>
#include <boost/test/unit_test.hpp>
#include <libjose/jws.hpp>
#include <libjose/jwk.hpp>

BOOST_AUTO_TEST_CASE(ConstructFromJson) {
    JOSE::JWS jws(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        ,
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ,
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    BOOST_CHECK_EQUAL(jws.header(), "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
    BOOST_CHECK_EQUAL(jws.payload(),
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    );
}

BOOST_AUTO_TEST_CASE(verify_oct) {
    JOSE::JWS jws(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        ,
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ,
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    JOSE::JWK jwk_oct_correct(
        "{"
            "\"kty\":\"oct\","
            "\"k\":\""
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
                "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
                "\""
        "}"
    );
    BOOST_CHECK(jws.verify(jwk_oct_correct));
    JOSE::JWK jwk_oct_error(
        "{"
            "\"kty\":\"oct\","
            "\"k\":\""
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
                "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAoa"
                "\""
        "}"
    );
    BOOST_CHECK(!jws.verify(jwk_oct_error));
}

BOOST_AUTO_TEST_CASE(sign_oct) {
    JOSE::JWS jws;
    jws.set_alg(
        JOSE::JWS::Alg::HS256
    );
    jws.set_payload(
        "{\"iss\":\"joe\",\n"
        " \"exp\":1300819380,\n"
        " \"http://example.com/is_root\":true}"
    );
    JOSE::JWK jwk_oct(
        "{"
            "\"kty\":\"oct\","
            "\"k\":\""
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
                "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
                "\""
        "}"
    );
    BOOST_CHECK(jws.sign(jwk_oct));
    BOOST_CHECK(jws.verify(jwk_oct));
}

BOOST_AUTO_TEST_CASE(verify_rsa) {
    JOSE::JWS jws(
        "eyJhbGciOiJSUzI1NiJ9"
        ,
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ,
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4"
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K"
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv"
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB"
        "p0igcN_IoypGlUPQGe77Rw"
    );
    JOSE::JWK jwk_rsa_correct(
        "{"
            "\"kty\":\"RSA\","
            "\"n\":\""
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
            "\",\"e\":\""
                "AQAB"
            "\""
        "}"
    );
    BOOST_CHECK(jws.verify(jwk_rsa_correct));
}

BOOST_AUTO_TEST_CASE(sign_rsa) {
    JOSE::JWS jws;
    jws.set_alg(
        JOSE::JWS::Alg::RS256
    );
    jws.set_payload(
        "{\"iss\":\"joe\",\n"
        " \"exp\":1300819380,\n"
        " \"http://example.com/is_root\":true}"
    );
    JOSE::JWK jwk_rsa_private(
        "{"
            "\"kty\":\"RSA\","
            "\"n\":\""
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
            "\",\"e\":\""
                "AQAB"
            "\",\"d\":\""
                "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
                "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
                "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
                "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
                "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
                "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
            "\",\"p\":\""
                "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
                "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
                "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
            "\",\"q\":\""
                "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
                "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
                "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
            "\",\"dp\":\""
                "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
                "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
                "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
            "\",\"dq\":\""
                "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
                "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
                "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
            "\",\"qi\":\""
                "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
                "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
                "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
            "\""
        "}"
    );
    BOOST_CHECK(jws.sign(jwk_rsa_private));
    JOSE::JWK jwk_rsa_public(
        "{"
            "\"kty\":\"RSA\","
            "\"n\":\""
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
            "\",\"e\":\""
                "AQAB"
            "\""
        "}"
    );
    BOOST_CHECK(jws.verify(jwk_rsa_public));
}
