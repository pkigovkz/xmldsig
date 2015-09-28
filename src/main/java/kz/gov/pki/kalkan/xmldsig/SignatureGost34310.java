package kz.gov.pki.kalkan.xmldsig;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Signature;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

public class SignatureGost34310
        extends SignatureAlgorithmSpi {

    private static final java.lang.String URI = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
    private static final String SIGN_ALG_NAME = "ECGOST3410";
    private Signature signature = null;

    SignatureGost34310()
            throws NoSuchAlgorithmException, NoSuchProviderException {
        signature = Signature.getInstance(SIGN_ALG_NAME, KalkanProvider.PROVIDER_NAME);
    }

    @Override
    protected String engineGetURI() {
        return URI;
    }

    @Override
    protected String engineGetJCEAlgorithmString() {
        return signature.getAlgorithm();
    }

    @Override
    protected String engineGetJCEProviderName() {
        return KalkanProvider.PROVIDER_NAME;
    }

    @Override
    protected void engineUpdate(byte[] bytes)
            throws XMLSignatureException {
        try {
            signature.update(bytes);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex.getLocalizedMessage());
        }
    }

    @Override
    protected void engineUpdate(byte b)
            throws XMLSignatureException {
        try {
            signature.update(b);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex.getLocalizedMessage());
        }
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1)
            throws XMLSignatureException {
        try {
            signature.update(bytes, i, i1);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex.getLocalizedMessage());
        }
    }

    @Override
    protected void engineInitSign(Key key)
            throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) key);
        } catch (InvalidKeyException ex) {
            throw new XMLSignatureException(ex.getLocalizedMessage());
        }
    }

    @Override
    protected void engineInitSign(Key key, SecureRandom sr)
            throws XMLSignatureException {
        try {
            signature.initSign((PrivateKey) key, sr);
        } catch (InvalidKeyException ex) {
            throw new XMLSignatureException(ex.getLocalizedMessage());
        }
    }

    @Override
    protected void engineInitSign(Key key, AlgorithmParameterSpec aps)
            throws XMLSignatureException {
        engineInitSign(key);
    }

    @Override
    protected byte[] engineSign()
            throws XMLSignatureException {
        byte[] result = null;

        try {
            result = signature.sign();
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex.getMessage());
        }

        return result;
    }

    @Override
    protected void engineInitVerify(Key key)
            throws XMLSignatureException {
        try {
            signature.initVerify((PublicKey) key);
        } catch (InvalidKeyException ex) {
            throw new XMLSignatureException(ex.getMessage());
        }
    }

    @Override
    protected boolean engineVerify(byte[] bytes)
            throws XMLSignatureException {
        boolean result = false;

        try {
            result = signature.verify(bytes);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex.getMessage());
        }

        return result;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec aps)
            throws XMLSignatureException {
        try {
            signature.setParameter(aps);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex.getMessage());
        }
    }

    @Override
    protected void engineSetHMACOutputLength(int i)
            throws XMLSignatureException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static class Gost34310Gost34311
            extends SignatureGost34310 {

        public static final java.lang.String _URI = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";

        public Gost34310Gost34311() throws NoSuchAlgorithmException, NoSuchProviderException {
        }

        @Override
        public java.lang.String engineGetURI() {
            return _URI;
        }
    }
}
