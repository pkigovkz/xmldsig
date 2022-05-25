package kz.gov.pki.kalkan.xmldsig;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignatureException;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureGostR3410_2015
        extends SignatureAlgorithmSpi {

    private static final String URI = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
    private static final String SIGN_ALG_NAME = "ECGOST3410-2015-512";
    private Signature signature = null;

    SignatureGostR3410_2015()
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

    public static class GostR34102015GostR34112015_512
            extends SignatureGostR3410_2015 {

        public static final String _URI = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";

        public GostR34102015GostR34112015_512() throws NoSuchAlgorithmException, NoSuchProviderException {
        }

        @Override
        public String engineGetURI() {
            return _URI;
        }
    }
}
