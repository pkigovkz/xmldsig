package kz.gov.pki.kalkan.xmldsig.keys.content.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.SignatureElementProxy;
import org.apache.xml.security.keys.content.x509.XMLX509DataContent;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XMLX509Certificate extends SignatureElementProxy implements XMLX509DataContent {

    /** Field JCA_CERT_ID */
    public static final String JCA_CERT_ID = "X.509";

    /**
     * Constructor X509Certificate
     *
     * @param element
     * @param baseURI
     * @throws XMLSecurityException
     */
    public XMLX509Certificate(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     * Constructor X509Certificate
     *
     * @param doc
     * @param certificateBytes
     */
    public XMLX509Certificate(Document doc, byte[] certificateBytes) {
        super(doc);

        this.addBase64Text(certificateBytes);
    }

    /**
     * Constructor XMLX509Certificate
     *
     * @param doc
     * @param x509certificate
     * @throws XMLSecurityException
     */
    public XMLX509Certificate(Document doc, X509Certificate x509certificate)
        throws XMLSecurityException {
        super(doc);

        try {
            this.addBase64Text(x509certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException ex) {
            throw new XMLSecurityException(ex);
        }
    }

    /**
     * Method getCertificateBytes
     *
     * @return the certificate bytes
     * @throws XMLSecurityException
     */
    public byte[] getCertificateBytes() throws XMLSecurityException {
        return this.getBytesFromTextChild();
    }

    /**
     * Method getX509Certificate
     *
     * @return the x509 certificate
     * @throws XMLSecurityException
     */
    public X509Certificate getX509Certificate() throws XMLSecurityException {
        byte[] certbytes = this.getCertificateBytes();
        try (InputStream is = new ByteArrayInputStream(certbytes)) {
            CertificateFactory certFact;
            try {
                certFact = CertificateFactory.getInstance(XMLX509Certificate.JCA_CERT_ID, "KALKAN");
            } catch (NoSuchProviderException e) {
                LOG.error("KalkanCrypt not found!");
                certFact = CertificateFactory.getInstance(XMLX509Certificate.JCA_CERT_ID);
            }
            return (X509Certificate) certFact.generateCertificate(is);
        } catch (CertificateException | IOException ex) {
            throw new XMLSecurityException(ex);
        }
    }

    /**
     * Method getPublicKey
     *
     * @return the publickey
     * @throws XMLSecurityException
     */
    public PublicKey getPublicKey() throws XMLSecurityException, IOException {
        X509Certificate cert = this.getX509Certificate();

        if (cert != null) {
            return cert.getPublicKey();
        }

        return null;
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof XMLX509Certificate)) {
            return false;
        }
        XMLX509Certificate other = (XMLX509Certificate) obj;
        try {
            return Arrays.equals(other.getCertificateBytes(), this.getCertificateBytes());
        } catch (XMLSecurityException ex) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        int result = 17;
        try {
            byte[] bytes = getCertificateBytes();
            for (byte element : bytes) {
                result = 31 * result + element;
            }
        } catch (XMLSecurityException e) {
            LOG.debug(e.getMessage(), e);
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public String getBaseLocalName() {
        return Constants._TAG_X509CERTIFICATE;
    }
}
