package cert.generate_type3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;






//import javax.security.cert.Certificate;
import sun.misc.BASE64Encoder;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import utils.ExportCertUtil;

import com.alibaba.fastjson.JSONObject;
 
@SuppressWarnings("restriction")
public class CertificateGenerationUtil {
	/**
	 * 
	 * @param CN 通用名
	 * @param OU :organization unit 组织单位名称 
	 * @param O :organization 组织名
	 * @param L :location 城市或区域名称 
	 * @param ST :state 州或省份名称
	 * @param C :country 国家名称
	 * @param alias
	 * @param password
	 * @param ksTargetPath
	 * @param certTargetPath
	 * @param validDay
	 * @return
	 */
    public static boolean generate(String CN,String OU,String O,String L,String ST,String C,String alias,String password,String ksTargetPath,String certTargetPath,int validDay ){
    	
        try{
            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();
            StringBuilder  argBuilder = new StringBuilder("CN=").append(CN).append(",OU=").append(OU).append(",O=").append(O)
            		.append(",L=").append(L).append(",ST=").append(ST).append(",C=").append(C);
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name(argBuilder.toString()), (long) validDay * 24 * 60 * 60);
            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
             
    		//String keystoreFile = "C:/mykeystore";
            KeyStore keyStore = KeyStore.getInstance("jks");
    		keyStore.load(null,password.toCharArray());
    		String keystoreFile = ksTargetPath;
            //Store the certificate
            storeKeyAndCertificate(keyStore,alias, password.toCharArray(), ksTargetPath, rootPrivateKey, rootCertificate);
            keyStore.load(new FileInputStream(new File(keystoreFile)), password.toCharArray());
            ExportCertUtil.exportCert(keyStore, alias, certTargetPath);
//            storeKeyAndCertificate(alias, password, "G:/key/aaa.jks", rootPrivateKey, rootCertificate);
            return true;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return false;
    }
     
    private static void storeKeyAndCertificateChain(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(null,null);
        keyStore.setKeyEntry(alias, key, password, chain);
        System.out.println(JSONObject.toJSONString(keyStore));
        keyStore.store(new FileOutputStream(keystore),password);
        
    }
    private static void storeKeyAndCertificate(KeyStore keyStore,String alias, char[] password, String ksFilePath, Key key, X509Certificate cert) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		keyStore.setKeyEntry(alias, key, password, new Certificate[] { cert });
		FileOutputStream outputStream = new FileOutputStream(ksFilePath);
		keyStore.store(outputStream, password);
//    	keyStore.store(new FileOutputStream(keystore),password);
		
		outputStream.flush();
		outputStream.close();
    }
     
    public static void loadAndDisplayChain(String alias,char[] password, String ksFilePath) throws Exception{
        //Reload the keystore
    	
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(ksFilePath),password);
         
        Key key=keyStore.getKey(alias, password);
        if(key instanceof PrivateKey){
            System.out.println("Get private key : ");
            System.out.println(key.toString());
             
            Certificate[] certs=keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            for(Certificate cert:certs){
                System.out.println(cert.toString());
              
            }
            
        }else{
            System.out.println("Key is not private key");
        }
    }
     
    private static void clearKeyStore(String alias,char[] password, String keystore) throws Exception{
    	/**
         * jceks The proprietary keystore implementation provided by the SunJCE provider. 
   		jks The proprietary keystore implementation provided by the SUN provider. 
   		dks A domain keystore is a collection of keystores presented as a single logical keystore. It is specified by configuration data whose syntax is described in DomainLoadStoreParameter. 
   		pkcs11 A keystore backed by a PKCS #11 token. 
   		pkcs12 
         */
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore),password);
        keyStore.deleteEntry(alias);
        keyStore.store(new FileOutputStream(keystore),password);
    }
     
    @SuppressWarnings("restriction")
    private static X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();
            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, (X500Name) issuer);
              
            //No need to add the BasicContraint for leaf cert
            if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }
              
            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);
              
            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
}