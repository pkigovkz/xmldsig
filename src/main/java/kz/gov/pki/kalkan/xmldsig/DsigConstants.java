package kz.gov.pki.kalkan.xmldsig;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.utils.Constants;

public class DsigConstants {
    
    public static final String ALGO_ID_SIGNATURE_RSA_SHA1 =
        Constants.MoreAlgorithmsSpecNS + "rsa-sha1";

    public static final String ALGO_ID_SIGNATURE_RSA_SHA256 =
        Constants.MoreAlgorithmsSpecNS + "rsa-sha256";

    public static final String ALGO_ID_SIGNATURE_ECGOST34310_2004_ECGOST34311_95 =
        Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";

    public static final String ALGO_ID_SIGNATURE_ECGOST3410_2015_ECGOST3411_2015_512 =
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";

    public static final String ALGO_ID_DIGEST_SHA1 =
        Constants.MoreAlgorithmsSpecNS + "sha1";

    public static final String ALGO_ID_DIGEST_SHA256 =
        MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;

    public static final String ALGO_ID_DIGEST_ECGOST34311_95 =
        Constants.MoreAlgorithmsSpecNS + "gost34311";

    public static final String ALGO_ID_DIGEST_ECGOST3411_2015_512 =
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
    
    private DsigConstants() {
    }

}
