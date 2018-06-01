/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestSignature.h"
#include "TestGlobal.h"

#include <QBuffer>

#include "crypto/OpenSSHKey.h"
#include "crypto/Crypto.h"
#include "crypto/Signature.h"

QTEST_GUILESS_MAIN(TestSignature)
static const char* rsa_private = ("-----BEGIN RSA PRIVATE KEY-----\n"
                                  "MIIEpAIBAAKCAQEAsCHtJicDPWnvHSIKbnTZaJkIB9vgE0pmLdK580JUqBuonVbB\n"
                                  "y1QTy0ZQ7/TtqvLPgwPK88TR46OLO/QGCzo2+XxgJ85uy0xfuyUYRmSuw0drsErN\n"
                                  "mH8vU91lSBxsGDp9LtBbgHKoR23vMWZ34IxFRc55XphrIH48ijsMaL6bXBwF/3tD\n"
                                  "9T3lm2MpP1huyVNnIY9+GRRWCy4f9LMj/UGu/n4RtwwfpOZBBRwYkq5QkzA9lPm/\n"
                                  "VzF3MP1rKTMkvAw+Nfb383mkmc6MRnsa6uh6iDa9aVB7naegM13UJQX/PY1Ks6pO\n"
                                  "XDpy/MQ7iCh+HmYNq5dRmARyaNl9xIXJNhz1cQIDAQABAoIBAQCnEUc1LUQxeM5K\n"
                                  "wANNCqE+SgoIClPdeHC7fmrLh1ttqe6ib6ybBUFRS31yXs0hnfefunVEDKlaV8K2\n"
                                  "N52UAMAsngFHQNRvGh6kEWeZPd9Xc+N98TZbNCjcT+DGKc+Om8wqH5DrodZlCq4c\n"
                                  "GaoT4HnE4TjWtZTH2XXrWF9I66PKFWf070R44nvyVcvaZi4pC2YmURRPuGF6K1iK\n"
                                  "dH8zM6HHG1UGu2W6hLNn+K01IulG0Lb8eWNaNYMmtQWaxyp7I2IWkkecUs3nCuiR\n"
                                  "byFOoomCjdh8r9yZFvwxjGUhgtkALN9GCU0Mwve+s11IB2gevruN+q9/Qejbyfdm\n"
                                  "IlgLAeTRAoGBANRcVzW9CYeobCf+U9hKJFEOur8XO+J2mTMaELA0EjWpTJFAeIT7\n"
                                  "KeRpCRG4/vOSklxxRF6vP1EACA4Z+5BlN+FTipHHs+bSEgqkPZiiANDH7Zot5Iqv\n"
                                  "1q0fRyldNRZNZK7DWp08BPNVWGA/EnEuKJiURxnxBaxNXbUyMCdjxvMvAoGBANRT\n"
                                  "utbrqS/bAa/DcHKn3V6DRqBl3TDOfvCNjiKC84a67F2uXgzLIdMktr4d1NyCZVJd\n"
                                  "7/zVgWORLIdg1eAi6rYGoOvNV39wwga7CF+m9sBY0wAaKYCELe6L26r4aQHVCX6n\n"
                                  "rnIgUv+4o4itmU2iP0r3wlmDC9pDRQP82vfvQPlfAoGASwhleANW/quvq2HdViq8\n"
                                  "Mje2HBalfhrRfpDTHK8JUBSFjTzuWG42GxJRtgVbb8x2ElujAKGDCaetMO5VSGu7\n"
                                  "Fs5hw6iAFCpdXY0yhl+XUi2R8kwM2EPQ4lKO3jqkq0ClNmqn9a5jQWcCVt9yMLNS\n"
                                  "fLbHeI8EpiCf34ngIcrLXNkCgYEAzlcEZuKkC46xB+dNew8pMTUwSKZVm53BfPKD\n"
                                  "44QRN6imFbBjU9mAaJnwQbfp6dWKs834cGPolyM4++MeVfB42iZ88ksesgmZdUMD\n"
                                  "szkl6O0pOJs0I+HQZVdjRbadDZvD22MHQ3+oST1dJ3FVXz3Cdo9qPuT8esMO6f4r\n"
                                  "qfDH2s8CgYAXC/lWWHQ//PGP0pH4oiEXisx1K0X1u0xMGgrChxBRGRiKZUwNMIvJ\n"
                                  "TqUu7IKizK19cLHF/NBvxHYHFw+m7puNjn6T1RtRCUjRZT7Dx1VHfVosL9ih5DA8\n"
                                  "tpbZA5KGKcvHtB5DDgT0MHwzBZnb4Q//Rhovzn+HXZPsJTTgHHy3NQ==\n"
                                  "-----END RSA PRIVATE KEY-----\n");
//static const char* rsa_private =
//        "-----BEGIN RSA PRIVATE KEY-----\n"
//        "MIIEowIBAAKCAQEAwGdladnqFfcDy02Gubx4sdBT8NYEg2YKXfcKLSwca5gV4X7I\n"
//        "z/+QR51LAfPCkj+QjWpj3DD1/6P7s6jOJ4BNd6CSDukv18DOsIsFn2D+zLmVoir2\n"
//        "lki3sTsmiEz65KvHE8EnQ8IzZCqZDC40tZOcz2bnkZrmcsEibKoxYsmQJk95NwdR\n"
//        "teFymp1qH3zq85xdNWw2u6c5CKzLgI5BjInttO98iSxL0KuY/JmzMx0gTbRiqc0x\n"
//        "22EODtdVsBoNL/pt8v6Q+WLpRg4/Yq7YurAngxk4h38NWvufj2vJvbcRqX4cupcu\n"
//        "92T9SWwSwZmd4Xy3bt+AUlq4XRMa1MlKfPvXmwIDAQABAoIBAGbWnRD/xaup1OBU\n"
//        "dr9N6qD3/fXLHqxw3PeudEUCv8oOhxt43bK3IZH1k8LeXFA5I3VCuU9W6BWUu5Mi\n"
//        "ldXtMPrQ22CW6NiEGLWqCP5QJMCeLUl5d0WKZoyXVhgiNTQGUKjRY8BGy5stXZJy\n"
//        "HAA1fuooUXu09Jm/ezvjl/P6Uk722nZns4g6cc8aUSQDSVoeuCvwDaix5o4Z4RGY\n"
//        "4biIKGj5qYxoe+rbgYH/2zlEcAiSJIuqjYY+Xk4IdB89DYZBYnO/xPkRaDeiY2xl\n"
//        "QM7Inr7PQC8PWJc9zYYvlGnnmIRCkO15mWau70N1Y1rUAsyW61g2GyFhdsIIODH/\n"
//        "878Kc9ECgYEA+2JaUqRWr6dqE+uVPpGkbGiAaRQ79olTcRmxXCnM+Y3c88z9G7kC\n"
//        "2S5UKPRDl7EzwmMJqqb8BZbdSWoAxO4++F6ylSz7TqowPw+13Wxwm3wApvr2Q1Mo\n"
//        "rkq4ltgyHMR+iXvKqOYa2GqZNmRwh7JGLIJ7Y0Z77nwBkkgDc/3ey8MCgYEAw+/N\n"
//        "fxv2t+r6VKxEtjdy3sfn8LLjiWqghPngJzcYH9NdB8fmMN1WHqX075hbKjI9TyJw\n"
//        "77p8onjZI0opLexHHUmepEa6Ijo1zynJJ7XPXnyruiTXXqz49io6lFOLcXi/i+DZ\n"
//        "B2vQcMGWA4qwJxz7KA6EZ/HimjuysV1guvlKf0kCgYA6+JGTvXWQc0eRMLysFuJp\n"
//        "hAJLpDGE3iYy7AINSskI6dyhXL8rl7UxWYroqJSKq0knGrCT1eRdM0zqAfH4QKOJ\n"
//        "BD4EfK7ff1EeGgNh1CR+dRJ6GXlXxdRPPrwattDaqsW8Xsvl30UA69DRT7KOQqXv\n"
//        "nxRu74P3KCP+OuKEfVOcnQKBgQC+/2r1Zj/5huBhW9BbQ/ABBSOuueMeGEfDeIUu\n"
//        "FQG6PGKqbA2TQp9pnuMGECGGH5UuJ+epeMN36Y/ZW7iKoJGuFg7EGoHlTZMYj6Yb\n"
//        "xJoRhDwuZy1eiATkicOyxUHf6hHme9dz6YA1+i+O4knWxuR5ZrVhUiRPrrQBO4JI\n"
//        "oSwiqQKBgHblgOVfOJrG3HDg6bo+qmxQsGFRCD0mehsg9YpokuZVX0UJtGx/RJHU\n"
//        "vIBL00An6YcNfPTSlNJeG83APtk/tdgsXvQd3pmIkeY78x6xWKSieZXv4lyDv7lX\n"
//        "r28lCTj2Ez2gEzEohZgf4V1uzBvTdJefarpQ00ep34UZ9FsNfUwD\n"
//        "-----END RSA PRIVATE KEY-----\n";
//static const char* rsa_public =
//        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAZ2Vp2eoV9wPLTYa5vHix0FPw1gSDZgpd9wotLBxrmBXhfsjP/5BHnUsB88KSP5CNamPcMPX/o/uzqM4ngE13oJIO6S/XwM6wiwWfYP7MuZWiKvaWSLexOyaITPrkq8cTwSdDwjNkKpkMLjS1k5zPZueRmuZywSJsqjFiyZAmT3k3B1G14XKanWoffOrznF01bDa7pzkIrMuAjkGMie2073yJLEvQq5j8mbMzHSBNtGKpzTHbYQ4O11WwGg0v+m3y/pD5YulGDj9irti6sCeDGTiHfw1a+5+Pa8m9txGpfhy6ly73ZP1JbBLBmZ3hfLdu34BSWrhdExrUyUp8+9eb hnh@Linux";
static const char* dsa_private =
        "-----BEGIN DSA PRIVATE KEY-----\n"
        "MIIBugIBAAKBgQDFBfBO/4eFUO9IIy8QaH6eXPWMuJuVByMMy9FGc9XUF/Tv5vzD\n"
        "9Qw7nU08/Zecl9aGYgYxvpTmEvEU6IFRYgu1ZllBjvWGBYGLebUQBcEGb0GhuZ7k\n"
        "C7oKQ7zGixlsmJXNInRH8zQaV0hXz5bAldIkrkq2edkPOO3cLE0viWm53wIVAPqA\n"
        "rY8jK6SRHrZKajPipSXuWdtZAoGADS1vrvYMJ/x0MzJXG2S1oc4Voju+C2UZBlLx\n"
        "bI5Dq2QoyowESbonoI11OB5EwiyPDTFp+3opCL/mQvjPRgRO2Uvnfo2KrteniEnt\n"
        "AhCEa6SUPqdNuEHF+dtAAJZPgaOPpRWGMPwuswhxSZxRPDwqOi/VhFsEwRKGV3SE\n"
        "3Zp8qE4CgYAGYnxiBYul01iFexef9y+FE+tzn4q0ES8ceqN8ftyJFvoqZEyesIse\n"
        "BfCtair4j1ffI6INaJs0D3rlmBgbm97pkYeYFumuRfhwJmSyz969dNN08Ovqco5H\n"
        "3osHRCwbUZNkhL7bXxovkCHZrSOFVEs8s5dthW7/Sbwul2otK+eqZwIUer5+jcnK\n"
        "MObJduJWVn+yDP1pzQE=\n"
        "-----END DSA PRIVATE KEY-----\n";
//static const char* dsa_public =
//        "ssh-dss AAAAB3NzaC1kc3MAAACBAMUF8E7/h4VQ70gjLxBofp5c9Yy4m5UHIwzL0UZz1dQX9O/m/MP1DDudTTz9l5yX1oZiBjG+lOYS8RTogVFiC7VmWUGO9YYFgYt5tRAFwQZvQaG5nuQLugpDvMaLGWyYlc0idEfzNBpXSFfPlsCV0iSuSrZ52Q847dwsTS+JabnfAAAAFQD6gK2PIyukkR62Smoz4qUl7lnbWQAAAIANLW+u9gwn/HQzMlcbZLWhzhWiO74LZRkGUvFsjkOrZCjKjARJuiegjXU4HkTCLI8NMWn7eikIv+ZC+M9GBE7ZS+d+jYqu16eISe0CEIRrpJQ+p024QcX520AAlk+Bo4+lFYYw/C6zCHFJnFE8PCo6L9WEWwTBEoZXdITdmnyoTgAAAIAGYnxiBYul01iFexef9y+FE+tzn4q0ES8ceqN8ftyJFvoqZEyesIseBfCtair4j1ffI6INaJs0D3rlmBgbm97pkYeYFumuRfhwJmSyz969dNN08Ovqco5H3osHRCwbUZNkhL7bXxovkCHZrSOFVEs8s5dthW7/Sbwul2otK+eqZw== hnh@Linux";

void TestSignature::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestSignature::testSigningUsingRSAPrivateKeyOnly()
{
    QByteArray data("Some trivial test with a longer .... ................................. longer text");

    OpenSSHKey rsaKey;
    rsaKey.parse(rsa_private);
    rsaKey.openPrivateKey(QString());
    Signature rsaSigner;
    const QString rsaSign = rsaSigner.create(data, rsaKey);
    ::qDebug() << /*rsaSigner.error() <<*/ rsaSign;
    //QVERIFY(rsaSigner.error().isEmpty());

    Signature rsaVerifier;
    const bool rsaVerified = rsaVerifier.verify(data, rsaSign, rsaKey);
    ::qDebug() << /*rsaSigner.error() << */ rsaSign << rsaVerified;
    //QCOMPARE(rsaVerified, true);
    //QVERIFY(rsaVerifier.error().isEmpty());

}

void TestSignature::testSigningUsingDSAPrivateKeyOnly()
{
    QByteArray data("Some trivial test");
    OpenSSHKey dsaKey;
    dsaKey.parse(dsa_private);
    dsaKey.openPrivateKey(QString());
    Signature dsaSigner;
    const QString dsaSign = dsaSigner.create(data, dsaKey);
    ::qDebug() << /*dsaSigner.error() <<*/ dsaSign;
    //QVERIFY(dsaSigner.error().isEmpty());

    Signature dsaVerifier;
    const bool dsaVerified = dsaVerifier.verify(data, dsaSign, dsaKey);
    ::qDebug() << /*dsaVerifier.error() << */ dsaSign << dsaVerified;
    //QVERIFY(dsaVerifier.error().isEmpty());
    //QCOMPARE(dsaVerified, true);
}
