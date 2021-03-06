package cert.validation;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
 



import org.apache.commons.io.IOUtils;

import sun.misc.BASE64Decoder;
 
public class CertChainValidator {
    /**
     * Validate keychain
     * @param client is the client X509Certificate
     * @param keyStore containing all trusted certificate
     * @return true if validation until root certificate success, false otherwise
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean validateKeyChain(X509Certificate client, KeyStore keyStore) throws KeyStoreException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        X509Certificate[] certs = new X509Certificate[keyStore.size()];
        System.out.println("size :"+keyStore.size());
        int i = 0;
        Enumeration<String> alias = keyStore.aliases();
 
        while (alias.hasMoreElements()) {
            X509Certificate cc = (X509Certificate) keyStore.getCertificate(alias.nextElement());
            certs[i++] = cc;
            System.out.println("ccccc>:"+cc.toString());
                    
        }
        System.out.println(">>>>>>client:");
        System.out.println(client.toString());
        System.out.println(">>>>>>trusted:");
        for(int j=0;j<certs.length-1;j++){
        	System.out.println(certs[j].toString());
        }
        return validateKeyChain(client, certs);
    }
 
    /**
     * Validate keychain:??????????????????????????????????????????????????????????????????????????????????????????
     * ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
     * @param client is the client X509Certificate
     * @param trustedCerts is Array containing all trusted X509Certificate
     * @return true if validation until root certificate success, false otherwise
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @SuppressWarnings("rawtypes")
	public static boolean validateKeyChain(X509Certificate client,
            X509Certificate... trustedCerts) throws CertificateException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        boolean found = false;
        int i = trustedCerts.length;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor anchor;
        Set anchors;
        CertPath path;
        List list;
        PKIXParameters params;
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
 
        while (!found && i > 0) {
            anchor = new TrustAnchor(trustedCerts[--i], null);
            anchors = Collections.singleton(anchor);
 
            list = Arrays.asList(new Certificate[] { client });
            path = cf.generateCertPath(list);
 
            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            String aaaString = client.getIssuerDN().getName();
            String bbbString = trustedCerts[i].getSubjectDN().getName();
            if (client.getIssuerDN().equals(trustedCerts[i].getSubjectDN())) {
                try {
                    validator.validate(path, params);
                    if (isSelfSigned(trustedCerts[i])) {
                        // found root ca
                        found = true;
                        System.out.println("validating root" + trustedCerts[i].getSubjectX500Principal().getName());
                    } else if (!client.equals(trustedCerts[i])) {
                        // find parent ca
                        System.out.println("validating via:" + trustedCerts[i].getSubjectX500Principal().getName());
                        found = validateKeyChain(trustedCerts[i], trustedCerts);
                    }
                } catch (CertPathValidatorException e) {
                	e.printStackTrace();
                    // validation fail, check next certifiacet in the trustedCerts array
                }
            }
        }
 
        return found;
    }
 
    /**
     *
     * @param cert is X509Certificate that will be tested
     * @return true if cert is self signed, false otherwise
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            PublicKey key = cert.getPublicKey();
 
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            return false;
        } catch (InvalidKeyException keyEx) {
            return false;
        }
    }
 
    public static void main(String... args) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException,
            InvalidAlgorithmParameterException, NoSuchProviderException {
    	
        String storename = "f:\\GenX509Cert\\RootCa.pfx";
        char[] storepass = "123456".toCharArray();
 
        KeyStore ks = KeyStore.getInstance("pkcs12");
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(storename);
            ks.load(fin, storepass);
            Certificate certificate = getCertificateFromFile("f:\\GenX509Cert\\ScriptX.crt");
            if (validateKeyChain((X509Certificate) certificate, ks)) {
                System.out.println("validate success");
            } else {
                System.out.println("validate fail");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(fin);
        }
 
    }
    private static Certificate getCertificateFromFile(String certificatePath)
    		throws Exception {
    	//???????????????????????????????????????????????????????????????-----BEGIN CERTIFICATE-----?????????????????????????????????
    	/*CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    	File file = new File(certificatePath);//????????????file????????????????????????FileReader
    	FileReader reader = new FileReader(file);//????????????fileReader????????????????????????BufferedReader
    	BufferedReader bReader = new BufferedReader(reader);//new??????BufferedReader???????????????????????????????????????
    	StringBuilder sb = new StringBuilder();//?????????????????????????????????????????????????????????
    	String s = "";
    	while ((s =bReader.readLine()) != null) {//???????????????????????????????????????????????????????????????
    		sb.append(s + "\n");//???????????????????????????????????????????????????????????????
    	}
    	bReader.close();
    	String certEntityString = sb.toString();
    	BASE64Decoder decoder = new BASE64Decoder();
    	byte[] byteCert = decoder.decodeBuffer(certEntityString);
    	//?????????????????????
    	ByteArrayInputStream bain = new ByteArrayInputStream(byteCert);
    	X509Certificate oCert = (X509Certificate)cf.generateCertificate(bain);
    	*/
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	 FileInputStream in = new FileInputStream(certificatePath);
         //???????????????????????????????????????????????????????????????-----BEGIN CERTIFICATE-----?????????????????????????????????
         Certificate certificate = cf.generateCertificate(in);
    	return certificate;
    }
}
