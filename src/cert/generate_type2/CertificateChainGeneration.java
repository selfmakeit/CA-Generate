package cert.generate_type2;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

//import javax.security.cert.Certificate;
import sun.misc.BASE64Encoder;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import com.alibaba.fastjson.JSONObject;
 
@SuppressWarnings("restriction")
public class CertificateChainGeneration {
    public static void main(String[] args){
    	
    	
        try{
            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);
             
            //Generate intermediate certificate
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen1.generate(1024);
            PrivateKey middlePrivateKey=keyGen1.getPrivateKey();
            X509Certificate middleCertificate = keyGen1.getSelfCertificate(new X500Name("CN=MIDDLE"), (long) 365 * 24 * 60 * 60);
            
            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen2.generate(1024);
            PrivateKey topPrivateKey=keyGen2.getPrivateKey();
            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP"), (long) 365 * 24 * 60 * 60);
            
            //Generate end certificate
            CertAndKeyGen keyGen3=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen3.generate(1024);
            PrivateKey endPrivateKey=keyGen3.getPrivateKey();
            X509Certificate endCertificate = keyGen3.getSelfCertificate(new X500Name("CN=END"), (long) 365 * 24 * 60 * 60);
            
            //Generate end certificate
            CertAndKeyGen keyGen4=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen4.generate(1024);
            PrivateKey endPrivateKey2=keyGen4.getPrivateKey();
            X509Certificate endCertificate2 = keyGen4.getSelfCertificate(new X500Name("CN=END2"), (long) 365 * 24 * 60 * 60);
             
            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            topCertificate    = createSignedCertificate(topCertificate,rootCertificate,rootPrivateKey);
            middleCertificate = createSignedCertificate(middleCertificate,topCertificate,topPrivateKey);
            endCertificate = createSignedCertificate(endCertificate,middleCertificate,middlePrivateKey);
            endCertificate2 = createSignedCertificate(endCertificate2,endCertificate,endPrivateKey);
            System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>key>>>>>");
            System.out.println(rootPrivateKey.toString());
            System.out.println(topPrivateKey.toString());
            System.out.println(middlePrivateKey.toString());
            X509Certificate[] chain = new X509Certificate[3];
            chain[1]=topCertificate;
            chain[0]=middleCertificate;
            chain[2]=rootCertificate;
            String alias = "mykey";
            char[] password = "123456".toCharArray();
            String keystore = "G:/exportCert/testkeys.jks";
             
            //Store the certificate chain
            storeKeyAndCertificateChain(alias, password, keystore, topPrivateKey, chain);
            //Reload the keystore and display key and certificate chain info
//            loadAndDisplayChain("mykey", "123456".toCharArray(), "testkeys.jks");
            loadAndDisplayChain(alias, password, keystore);
            //Clear the keystore
//            clearKeyStore(alias, password, keystore);
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }
     
    private static void storeKeyAndCertificateChain(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(null,null);
        int i=0;
        for(Certificate cert:chain){
        	System.out.println("alias>>>>>: "+alias+i);
        	keyStore.setCertificateEntry(alias+i, chain[i++]);
        	keyStore.setKeyEntry(alias, key, password, chain);
            BASE64Encoder encoder = new BASE64Encoder();
            String encoded = encoder.encode(cert.getEncoded());
            String nnString= ((X509Certificate)cert).getSubjectDN().toString().substring(3);
            FileWriter fw = new FileWriter("G:/exportCert/cms"+nnString+".cer");
//		fw.write("-----BEGIN CERTIFICATE-----\r\n");	//非必须
            fw.write(encoded);
//		fw.write("\r\n-----END CERTIFICATE-----");	//非必须
            fw.close();
        }
        keyStore.store(new FileOutputStream(keystore),password);
        
    }
    private static void storeKeyAndCertificate(String alias, char[] password, String ksFilePath, Key key, X509Certificate cert) throws Exception{
    	KeyStore keyStore=KeyStore.getInstance("jks");
    	keyStore.load(null,password);
    	keyStore.setKeyEntry(alias, key, password, new Certificate[] { cert });
    	FileOutputStream outputStream = new FileOutputStream(ksFilePath);
    	keyStore.store(outputStream, password);
//    	keyStore.store(new FileOutputStream(keystore),password);
    	
    	outputStream.flush();
    	outputStream.close();
    	
    }
     
    private static void loadAndDisplayChain(String alias,char[] password, String keystore) throws Exception{
        //Reload the keystore
    	
        KeyStore keyStore=KeyStore.getInstance("jks");
        
        keyStore.load(new FileInputStream(keystore),password);
         
        Key key=keyStore.getKey(alias, password);
        if(key instanceof PrivateKey){
            System.out.println("Get private key : ");
            System.out.println(key.toString());
             
            Certificate[] certs=keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            int i=0;
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
            if(!cetrificate.getSubjectDN().getName().equals("CN=MIDDLE")){
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