package cert.validator;

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

import cert.generate_type4.CertParamEntity;
import cert.generate_type4.GenX509CertGenerator;
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
//        System.out.println("size :"+keyStore.size());
        int i = 0;
        Enumeration<String> alias = keyStore.aliases();
 
        while (alias.hasMoreElements()) {
            X509Certificate cc = (X509Certificate) keyStore.getCertificate(alias.nextElement());
            certs[i++] = cc;
                    
        }
//        for(int j=0;j<certs.length-1;j++){
//        	System.out.println(certs[j].toString());
//        }
        return validateKeyChain(client, certs);
    }
 
    /**
     * Validate keychain:验证思路：判断证书的发布者是否在可信任列表，不是则验证失败，
     * 是则验证发布者的证书的发布者是否在可信任列表，在可信任列表则验证发布者的证书是不是自签名证书。。。依此递归
     * @param client is the client X509Certificate
     * @param trustedCerts is Array containing all trusted X509Certificate
     * @return true if validation until root certificate success, false otherwise
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @SuppressWarnings("rawtypes")
	public static boolean validateKeyChain(X509Certificate client,X509Certificate... trustedCerts) throws CertificateException,
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
//                        System.out.println("validating root" + trustedCerts[i].getSubjectX500Principal().getName());
                    } else if (!client.equals(trustedCerts[i])) {
                        // find parent ca
//                        System.out.println("validating via:" + trustedCerts[i].getSubjectX500Principal().getName());
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
 
    public static boolean checkCert(String rootKsPath,String rootKsPwd,String needCheckCaPath)  {
    	
        String storename = rootKsPath;
        char[] storepass = rootKsPwd.toCharArray();
 
        FileInputStream fin = null;
        try {
        	KeyStore ks = KeyStore.getInstance("pkcs12");
            fin = new FileInputStream(storename);
            ks.load(fin, storepass);
            Certificate certificate = getCertificateFromFile(needCheckCaPath);
            
//           System.out.println(certificate.toString());
            if (validateKeyChain((X509Certificate) certificate, ks)) {
//                System.out.println("validate success");
                return true;
            } else {
//                System.out.println("validate fail");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(fin);
        }
        return false;
    }
    private static Certificate getCertificateFromFile(String certificatePath)
    		throws Exception {
    	//下面这种方式从文件创建证书时要求文件里没有-----BEGIN CERTIFICATE-----开始标记，以及结束标记
    	/*CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    	File file = new File(certificatePath);//定义一个file对象，用来初始化FileReader
    	FileReader reader = new FileReader(file);//定义一个fileReader对象，用来初始化BufferedReader
    	BufferedReader bReader = new BufferedReader(reader);//new一个BufferedReader对象，将文件内容读取到缓存
    	StringBuilder sb = new StringBuilder();//定义一个字符串缓存，将字符串存放缓存中
    	String s = "";
    	while ((s =bReader.readLine()) != null) {//逐行读取文件内容，不读取换行符和末尾的空格
    		sb.append(s + "\n");//将读取的字符串添加换行符后累加存放在缓存中
    	}
    	bReader.close();
    	String certEntityString = sb.toString();
    	BASE64Decoder decoder = new BASE64Decoder();
    	byte[] byteCert = decoder.decodeBuffer(certEntityString);
    	//转换成二进制流
    	ByteArrayInputStream bain = new ByteArrayInputStream(byteCert);
    	X509Certificate oCert = (X509Certificate)cf.generateCertificate(bain);
    	*/
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	 FileInputStream in = new FileInputStream(certificatePath);
         //使用这种方式从文件创建证书时，文件里必须有-----BEGIN CERTIFICATE-----开始标记，以及结束标记
         Certificate certificate = cf.generateCertificate(in);
    	return certificate;
    }
    
    public static void main(String[] args) {
    	CertParamEntity rootParam = new CertParamEntity();
		rootParam.setDnName("CN=RootCA,OU=hackwp,O=wp,L=BJ,S=BJ,C=CN");
		rootParam.setCaAlias("RootCA");
		rootParam.setCaKeyStorePwd("123456");
		rootParam.setCaPath("f:\\GenX509Cert\\RootCa.crt");
		rootParam.setCaKeyStorePath("f:\\GenX509Cert\\RootCa.pfx");
		rootParam.setValidDay(3650);
        X509Certificate rootCa = GenX509CertGenerator.generateSignedCert(null,rootParam);
        CertParamEntity childParam = new CertParamEntity();
        childParam.setDnName("CN=childCA, OU=wps, O=wps, L=BJ, ST=BJ, C=CN");
        childParam.setCaAlias("childCA");
        childParam.setCaKeyStorePwd("123456");
        childParam.setCaPath("F:\\GenX509Cert\\childCa.crt");
        childParam.setCaKeyStorePath("f:\\GenX509Cert\\childCa.pfx");
        childParam.setCaprivateKeyPath("F:\\GenX509Cert\\childCa.pvk");;
        childParam.setValidDay(365);
        X509Certificate childCa = GenX509CertGenerator.generateSignedCert(rootParam,childParam);
//        
    	boolean st = CertChainValidator.checkCert(rootParam.getCaKeyStorePath(), rootParam.getCaKeyStorePwd(), rootParam.getCaPath());
    	if (st) {
   		 System.out.println("rootCA validate success");
		}else {
			System.out.println("rootCA validate fail");
		}
	}
    
}
