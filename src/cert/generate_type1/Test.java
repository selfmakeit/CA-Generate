package cert.generate_type1;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Test {

	public static void main(String[] args)  {
		try {
		 // 创建密钥对，两种算法选择
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
//        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
//        gen.initialize(571);
        KeyPair pair = gen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        /**
         *  准备生成CA证书
         */
        // 创建 CSR 对象
        X500Principal subject = new X500Principal("C=CName, ST=bc, L=bc, O=bc, OU=OUName, CN=CNName, EMAILADDRESS=bc@bochtec.com");
//        ContentSigner signGen = new JcaContentSignerBuilder("SHA256withECDSA").build(privateKey);
        ContentSigner signGen = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        // 添加 SAN 扩展
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        GeneralNames generalNames = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.rfc822Name, "ip=6.6.6.6"), new GeneralName(GeneralName.rfc822Name, "email=666@gmail.com")});
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, generalNames);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        // build csr
        PKCS10CertificationRequest csr = builder.build(signGen);

        File file = new File("F:\\jiang-ca3.cer");
        FileOutputStream outputStream = new FileOutputStream(file);

        // 输出 PEM 格式的 CSR
        OutputStreamWriter output = new OutputStreamWriter(outputStream);
        JcaPEMWriter pem = new JcaPEMWriter(output);
			pem.writeObject(csr);
			System.err.println("=============CA证书生成==============");
			pem.close();
		} catch (IOException | NoSuchAlgorithmException | OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		checkCer();
	}
	 public static void checkCer() {
		 String certificatePath = "F:\\ScriptX.crt";

		 CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X509");
			X509Certificate certificate = null;
			
			X509CRLEntry revokedCertificate = null;
			
			X509CRL crl = null;
			
			certificate = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certificatePath)));
			System.out.println(">>>v>"+certificate.getVersion());
			certificate.checkValidity();
			URL url = new URL("http://.crl");
			
			URLConnection connection = url.openConnection();
			
			try(DataInputStream inStream = new DataInputStream(connection.getInputStream())){
				
				crl = (X509CRL)cf.generateCRL(inStream);
				
			} catch (IOException | CRLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
			
			if(revokedCertificate !=null){
				
				System.out.println("Revoked");
				
			}
			
			else{
				
				System.out.println("Valid");
				
			}
		} catch (CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
