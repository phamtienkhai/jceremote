package com.khaica.provider.jceremote.main;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.khaica.provider.JCERemote;
import com.khaica.provider.jceremote.JCERemotePrivateKey;
import com.khaica.provider.jceremote.client.RemoteSigner;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

public class XMLSigner {

    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    public static final String DIGESTALGORITHM = "DIGESTALGORITHM";
    private static final String SIGNATURE_ALGORITHM_PREFIX = "with";
    private static final String DIGEST_METHOD_URI_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

    protected static final String SIGNATURE_METHOD_RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    protected static final String SIGNATURE_METHOD_RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    protected static final String SIGNATURE_METHOD_RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    protected static final String SIGNATURE_METHOD_ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    protected static final String SIGNATURE_METHOD_ECDSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    protected static final String SIGNATURE_METHOD_ECDSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    protected static final String SIGNATURE_METHOD_ECDSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    protected static final String SIGNATURE_METHOD_DSA_SHA256 =
            "http://www.w3.org/2009/xmldsig11#dsa-sha256";

    protected String signatureAlgorithm;
    protected String digestAlgorithmString;
    protected String digestMethod;
    
    private static PrivateKey privateKey;

    public byte[] processData(String aliase, String providerName, byte[] dataToSign, String signatureAlgorithm, String digestAlgorithmString, Properties properties){
        this.digestAlgorithmString = digestAlgorithmString;
        this.signatureAlgorithm = signatureAlgorithm;
//        properties.setProperty("digestAlgorithmString", digestAlgorithmString);
//        properties.setProperty("signatureAlgorithm")
//        System.out.println("this.digestAlgorithmString:"+this.digestAlgorithmString);
//        KeyStore keyStore = KeyStoreUtils.getKeyStore(aliase, "123456");
//        KeyStore keyStore = KeyStoreUtils.getKeyStore(aliase, "123456", "D:\\khaipt.p12");
        try {
        	JCERemotePrivateKey privateKey = new JCERemotePrivateKey();
            privateKey.setKeyId("KhaiPT");
            String certificateString = RemoteSigner.remoteGetCertificate("KhaiPT");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream is = new ByteArrayInputStream(java.util.Base64.getDecoder().decode(certificateString));
            Certificate certificate = factory.generateCertificate(is);
            Certificate[] certificates = new Certificate[] { certificate };
            List<Certificate> certificatesList = new ArrayList<Certificate>();
            for(Certificate certificate2 : certificates){
                certificatesList.add(certificate);
            }
//            org.apache.jcp.xml.dsig.internal.dom.DOMSignatureMethod.
//            byte[] dataSigned = sign(dataToSign, certificatesList, privateKey, providerName);
//            XPathService service = new XPathService();
            byte[] dataSigned = sign(dataToSign, certificatesList, privateKey, providerName, digestAlgorithmString, signatureAlgorithm);
//            String dataSignedBase64 = java.util.Base64.getEncoder().encodeToString(dataSigned);
//            return dataSignedBase64;
//            System.out.println(new );
            return dataSigned;
        } catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }

    public byte[] sign(byte[] dataToSign, List<Certificate> certs, PrivateKey privateKey, String providerName, String digestAlgorithmString, String signatureAlgorithm){
        Provider provider = Security.getProvider("ApacheXMLDSig");
        if(provider == null){
            Security.addProvider(new XMLDSigRI());
        }
        XMLSignatureFactory factory = null;
        try {
            factory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        Certificate cert = null;
        Document doc = null;
        try {
            // Get certificate chain and signer certificate
            if (certs == null) {
                throw new IllegalArgumentException("Null certificate chain. This signer needs a certificate.");
            }
            List x509CertChain = new LinkedList<>();
            for (Certificate c : certs) {
                if (c instanceof X509Certificate) {
                	X509Certificate certificate2 = (X509Certificate) c;
                	x509CertChain.add("SerialNumber="+certificate2.getSerialNumber()+", "+certificate2.getSubjectDN().getName());
                    x509CertChain.add((X509Certificate) c);
                }
            }
            cert = certs.get(0);

            // Private key
            final PrivateKey privKey = privateKey;

            SignedInfo si = null;
            try {
                final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(privKey) : signatureAlgorithm;

                // find digest method if DIGESTALGORITHM not provided
                if (digestMethod == null) {
                    digestMethod = getDigestMethodFromDigestAlgorithmString((digestAlgorithmString));
                }

                Reference ref = factory.newReference("",
                        factory.newDigestMethod(digestMethod, null),
                        Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (XMLStructure) null)),
                        null, null);

//                System.out.println("sigAlg:"+getSignatureMethod(sigAlg));
                si = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (XMLStructure) null),
                        factory.newSignatureMethod(getSignatureMethod(sigAlg), null),
                        Collections.singletonList(ref));

            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }

            KeyInfo ki = null;

            if (!x509CertChain.isEmpty()) {
                KeyInfoFactory kif = factory.getKeyInfoFactory();
                X509Data x509d = kif.newX509Data(x509CertChain);
//                org.apache.xml.security.keys.content.X509Data x509Data = new org.apache.xml.security.keys.content.X509Data(doc)
//                x509Data.
//                KeyInfo
//                x509d.
//                kif.

                List<XMLStructure> kviItems = new LinkedList<>();
                kviItems.add(x509d);
//                kviItems.add
            
                ki = kif.newKeyInfo(kviItems);
//                ki = kif.newKeyInfo(Collections.singletonList(x509d));
            }

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            try {
                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

                // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
                // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

                // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

                ByteArrayInputStream in = new ByteArrayInputStream(dataToSign);
                doc = dbf.newDocumentBuilder().parse(in);
            } catch (SAXException ex) {
                ex.printStackTrace();
            } catch (ParserConfigurationException | IOException ex) {
                ex.printStackTrace();
            }
            DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement());
            dsc.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", Security.getProvider(providerName));

            XMLSignature signature = factory.newXMLSignature(si, ki);
            try {
                signature.sign(dsc);
            } catch (MarshalException | XMLSignatureException ex) {
                ex.printStackTrace();
            }
        } finally {
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans;
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
            byte[] dataSigned = os.toByteArray();
//            System.out.println(new String(dataSigned));
            return dataSigned;
        } catch (TransformerException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    protected static String getSignatureMethod(final String sigAlg)
            throws NoSuchAlgorithmException {
        String result;

        if ("SHA1withDSA".equals(sigAlg)) {
            result = SignatureMethod.DSA_SHA1;
        } else if ("SHA256withDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_DSA_SHA256;
        } else if ("SHA1withRSA".equals(sigAlg)) {
            result = SignatureMethod.RSA_SHA1;
        } else if ("SHA256withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA256;
        } else if ("SHA384withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA384;
        } else if ("SHA512withRSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_RSA_SHA512;
        } else if ("SHA1withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA1;
        } else if ("SHA256withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA256;
        } else if ("SHA384withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA384;
        } else if ("SHA512withECDSA".equals(sigAlg)) {
            result = SIGNATURE_METHOD_ECDSA_SHA512;
        } else {
            throw new NoSuchAlgorithmException("XMLSigner does not support algorithm: " + sigAlg);
        }

        return result;
    }


    protected String getDefaultSignatureAlgorithm(final PrivateKey privKey) {
        final String result;

        if (privKey instanceof DSAPrivateKey) {
            result = "SHA256withDSA";
        } else if (privKey instanceof ECPrivateKey) {
            result = "SHA256withECDSA";
        } else {
            result = "SHA256withRSA";
        }

        return result;
    }

    protected String getDefaultDigestMethodFromSignatureAlgorithm(String sigAlg) throws NoSuchAlgorithmException {
        String result;

        // Extract digest algorithm from signature algorithm
        String digestAlg = sigAlg.substring(0, sigAlg.indexOf(SIGNATURE_ALGORITHM_PREFIX));

        switch (digestAlg) {
            case "SHA1":
                result = DigestMethod.SHA1;
                break;
            case "SHA256":
                result = DigestMethod.SHA256;
                break;
            case "SHA384":
                result = DIGEST_METHOD_URI_SHA384;
                break;
            case "SHA512":
                result = DigestMethod.SHA512;
                break;
            default:
                throw new NoSuchAlgorithmException("XMLSigner does not support signature algorithm: " + sigAlg);
        }

        return result;
    }

    protected String getDigestMethodFromDigestAlgorithmString(String digestAlgorithm) throws NoSuchAlgorithmException {
        String result;

        switch (digestAlgorithm) {
            case "SHA1":
            case "SHA-1":
                result = DigestMethod.SHA1;
                break;
            case "SHA256":
            case "SHA-256":
                result = DigestMethod.SHA256;
                break;
            case "SHA384":
            case "SHA-384":
                result = DIGEST_METHOD_URI_SHA384;
                break;
            case "SHA512":
            case "SHA-512":
                result = DigestMethod.SHA512;
                break;
            case "RIPEMD160":
            case "RIPEMD-160":
                result = DigestMethod.RIPEMD160;
                break;
            default:
                throw new NoSuchAlgorithmException("XMLSigner does not support digest algorithm: " + digestAlgorithm);
        }
        return result;
    }

    public static void main(String[] args) {
        Security.addProvider(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
//        ProviderUtils.getAlg("ApacheXMLDSig");
//        Provider provider = Security.getProvider("ApacheXMLDSigaaaaa");
//        System.out.println(provider);
        Security.addProvider(new JCERemote());
        XMLSigner signer = new XMLSigner();
        byte[] dataSigned = signer.processData("tupk_rsa", "JCERemote", "<xml>hello world</xml>".getBytes(), "SHA256withRSA", "SHA256", null);
        System.out.println(new String(dataSigned));
    }
}
