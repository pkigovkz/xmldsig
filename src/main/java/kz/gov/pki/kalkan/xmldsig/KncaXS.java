package kz.gov.pki.kalkan.xmldsig;

public class KncaXS {
	public static void loadXMLSecurity() {
		System.setProperty("org.apache.xml.security.resource.config", "/kz/gov/pki/kalkan/xmldsig/pkigovkz.xml");
		org.apache.xml.security.Init.init();
		org.apache.xml.security.algorithms.JCEMapper.setProviderId("KALKAN");
	}

	private KncaXS() {
	}
}
