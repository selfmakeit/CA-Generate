package cert.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
 

import java.util.Enumeration;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import com.alibaba.fastjson.JSONObject;

import sun.misc.BASE64Encoder;
 
/**
 * 根据keyStore文件导出证书(base64)，导出私钥，导出公钥
 */
public class ExportCertUtil {
	
	 //导出证书 base64格式  
    @SuppressWarnings("restriction")
	public static void exportCert(KeyStore keystore, String alias, String exportFile) throws Exception {  
        Certificate cert = keystore.getCertificate(alias);  
        BASE64Encoder encoder = new BASE64Encoder();  
        String encoded = encoder.encode(cert.getEncoded());  
        FileWriter fw = new FileWriter(exportFile);  
        fw.write("-----BEGIN CERTIFICATE-----\r\n");    //非必须  
        fw.write(encoded);  
        fw.write("\r\n-----END CERTIFICATE-----");  //非必须  
        fw.close();  
    }  
  
	//得到KeyPair
	public static KeyPair getKeyPair(KeyStore keystore, String alias,char[] password) {
		try {
			Key key = keystore.getKey(alias, password);
			if (key instanceof PrivateKey) {
				Certificate cert = keystore.getCertificate(alias);
				PublicKey publicKey = cert.getPublicKey();
				return new KeyPair(publicKey, (PrivateKey) key);
			}
		} catch (UnrecoverableKeyException e) {
		} catch (NoSuchAlgorithmException e) {
		} catch (KeyStoreException e) {
		}
		return null;
	}
 
	//导出私钥
	@SuppressWarnings("restriction")
	public static void exportPrivateKey(PrivateKey privateKey,String exportFile) throws Exception {
		BASE64Encoder encoder = new BASE64Encoder();
		String encoded = encoder.encode(privateKey.getEncoded());
		FileWriter fw = new FileWriter(exportFile);
		fw.write("—–BEGIN PRIVATE KEY—–\r\n");	//非必须
		fw.write(encoded);
		fw.write("\r\n—–END PRIVATE KEY—–");		//非必须
		fw.close();
	}
	
	//导出公钥
	public static void exportPublicKey(PublicKey publicKey,String exportFile) throws Exception {
		BASE64Encoder encoder = new BASE64Encoder();
		String encoded = encoder.encode(publicKey.getEncoded());
		FileWriter fw = new FileWriter(exportFile);
		fw.write("—–BEGIN PUBLIC KEY—–\r\n");		//非必须
		fw.write(encoded);
		fw.write("\r\n—–END PUBLIC KEY—–");		//非必须
		fw.close();
	}
 
	public static void main(String args[]) throws Exception {
		
		
		
		String keyStoreType = "JKS";
		//String keystoreFile = "C:/mykeystore";
		String keystoreFile = "G:/key/aaa.jks";
		String password = "123456";
		
		KeyStore keystore = KeyStore.getInstance(keyStoreType);
		keystore.load(new FileInputStream(new File(keystoreFile)), password.toCharArray());
		
		String alias = "mykey";
		String exportCertFile = "G:/exportCert/aaa.cer";	
		String exportPrivateFile = "G:/exportCert/aaaPrivateKey.txt";
		String exportPublicFile = "G:/exportCert/aaaPublicKey.txt";
		
		ExportCertUtil.exportCert(keystore, alias, exportCertFile);
		KeyPair keyPair = ExportCertUtil.getKeyPair(keystore, alias, password.toCharArray());
		ExportCertUtil.exportPrivateKey(keyPair.getPrivate(), exportPrivateFile);
		ExportCertUtil.exportPublicKey(keyPair.getPublic(), exportPublicFile);
		
		System.out.println("OK");
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
            	 File file = new File("G:/exportCert/cms"+i+++".cer");
                 FileOutputStream outputStream = new FileOutputStream(file);

                 // 输出 PEM 格式的 CSR
                 OutputStreamWriter output = new OutputStreamWriter(outputStream);
                 
                 JcaPEMWriter pem = new JcaPEMWriter(output);
         			pem.writeObject(cert);
         			pem.close();
            	
//                System.out.println(cert.toString());
//                
//                
//                BASE64Encoder encoder = new BASE64Encoder();
//                String encoded = encoder.encode(cert.getEncoded());
//                FileWriter fw = new FileWriter("G:/exportCert/cms"+i+++".cer");
//                fw.write(encoded);
////    		fw.write("\r\n-----END CERTIFICATE-----");	//非必须
//                fw.close();
            }
            
        }else{
            System.out.println("Key is not private key");
        }
    }
     
	
}
