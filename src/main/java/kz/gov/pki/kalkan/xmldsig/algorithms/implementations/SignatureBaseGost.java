package kz.gov.pki.kalkan.xmldsig.algorithms.implementations;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Signature;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;
import kz.gov.pki.kalkan.xmldsig.DsigConstants;

public abstract class SignatureBaseGost
        extends SignatureAlgorithmSpi {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SignatureBaseGost.class);
    private final Signature signature;

    public SignatureBaseGost() throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
        signature = getSignature(algorithmID);
        LOG.debug("Created SignatureGOST using {} and provider {}", algorithmID, signature.getProvider());
    }

    Signature getSignature(String algorithmID) throws XMLSignatureException {
        try {
            String providerId = JCEMapper.getProviderId();
            return Signature.getInstance(algorithmID, providerId);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = {algorithmID, ex.getLocalizedMessage()};
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    @Override
    protected String engineGetJCEAlgorithmString() {
        return signature.getAlgorithm();
    }

    @Override
    protected String engineGetJCEProviderName() {
        return signature.getProvider().getName();
    }

    @Override
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            signature.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            signature.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            signature.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineInitSign(Key key) throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) key);
        } catch (InvalidKeyException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineInitSign(Key key, SecureRandom sr) throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) key, sr);
        } catch (InvalidKeyException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineInitSign(Key key, AlgorithmParameterSpec params) throws XMLSignatureException {
        engineInitSign(key);
    }

    @Override
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return signature.sign();
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineInitVerify(Key key) throws XMLSignatureException {
        engineInitVerify(key, signature);
    }

    @Override
    protected boolean engineVerify(byte[] bytes) throws XMLSignatureException {
        try {
            return signature.verify(bytes);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws XMLSignatureException {
        try {
            signature.setParameter(params);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    @Override
    protected void engineSetHMACOutputLength(int i) throws XMLSignatureException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static class Gost34310Gost34311
            extends SignatureBaseGost {

        public Gost34310Gost34311() throws XMLSignatureException {
            super();
        }

        @Override
        public String engineGetURI() {
            return DsigConstants.ALGO_ID_SIGNATURE_ECGOST34310_2004_ECGOST34311_95;
        }
    }

    public static class GostR34102015GostR34112015_512
            extends SignatureBaseGost {

        public GostR34102015GostR34112015_512() throws XMLSignatureException {
            super();
        }

        @Override
        public String engineGetURI() {
            return DsigConstants.ALGO_ID_SIGNATURE_ECGOST3410_2015_ECGOST3411_2015_512;
        }
    }
}
