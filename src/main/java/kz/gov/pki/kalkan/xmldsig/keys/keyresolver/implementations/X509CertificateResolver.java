package kz.gov.pki.kalkan.xmldsig.keys.keyresolver.implementations;

import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import kz.gov.pki.kalkan.xmldsig.keys.content.x509.XMLX509Certificate;

public class X509CertificateResolver extends KeyResolverSpi {
	/** {@link org.apache.commons.logging} logging facility */
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(X509CertificateResolver.class);

    /**
     * Method engineResolvePublicKey
     * @inheritDoc
     * @param element
     * @param BaseURI
     * @param storage
     *
     * @throws KeyResolverException
     */
    public PublicKey engineLookupAndResolvePublicKey(
        Element element, String BaseURI, StorageResolver storage
    ) throws KeyResolverException {

        X509Certificate cert = 
            this.engineLookupResolveX509Certificate(element, BaseURI, storage);

        if (cert != null) {
            return cert.getPublicKey();
        }

        return null;
    }

    /**
     * Method engineResolveX509Certificate
     * @inheritDoc
     * @param element
     * @param BaseURI
     * @param storage
     *
     * @throws KeyResolverException
     */
    public X509Certificate engineLookupResolveX509Certificate(
        Element element, String BaseURI, StorageResolver storage
    ) throws KeyResolverException {

        try {
            Element[] els = 
                XMLUtils.selectDsNodes(element.getFirstChild(), Constants._TAG_X509CERTIFICATE);
            if ((els == null) || (els.length == 0)) {  
                Element el =
                    XMLUtils.selectDsNode(element.getFirstChild(), Constants._TAG_X509DATA, 0);
                if (el != null) {
                    return engineLookupResolveX509Certificate(el, BaseURI, storage);
                }        	 
                return null;            
            }

            // populate Object array
            for (int i = 0; i < els.length; i++) {
                XMLX509Certificate xmlCert = new XMLX509Certificate(els[i], BaseURI);
                X509Certificate cert = xmlCert.getX509Certificate();
                if (cert != null) {
                    return cert;
                }
            }
            return null;
        } catch (XMLSecurityException ex) {
            if (log.isDebugEnabled()) {
                log.debug("XMLSecurityException", ex);
            }
            throw new KeyResolverException("generic.EmptyMessage", ex);
        }
    }

    /**
     * Method engineResolveSecretKey
     * @inheritDoc
     * @param element
     * @param BaseURI
     * @param storage
     */
    public javax.crypto.SecretKey engineLookupAndResolveSecretKey(
        Element element, String BaseURI, StorageResolver storage
    ) {
        return null;
    }
}
