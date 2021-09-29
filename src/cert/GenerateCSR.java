package cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import sun.security.provider.X509Factory;
import sun.misc.BASE64Encoder;
import sun.security.util.DerValue;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;


import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import sun.security.pkcs10.*;
import sun.security.x509.*;

@SuppressWarnings("restriction")
public class GenerateCSR {
    private static PublicKey publicKey = null;
    private static PrivateKey privateKey = null;
    private static KeyPairGenerator keyGen = null;
    private static GenerateCSR gcsr = null;

    private GenerateCSR() {
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        publicKey = keypair.getPublic();
        privateKey = keypair.getPrivate();
    }

    public static GenerateCSR getInstance() {
        if (gcsr == null)
            gcsr = new GenerateCSR();
        return gcsr;
    }

    public String getCSR(String cn) throws Exception {
        byte[] csr = generatePKCS10(cn, "Java", "JournalDev", "Cupertino",
                "California", "USA");
        return new String(csr);
    }

    /**
     *
     * @param CN
     *            Common Name, is X.509 speak for the name that distinguishes
     *            the Certificate best, and ties it to your Organization
     * @param OU
     *            Organizational unit
     * @param O
     *            Organization NAME
     * @param L
     *            Location
     * @param S
     *            State
     * @param C
     *            Country
     * @return
     * @throws Exception
     */
    private static byte[] generatePKCS10(String CN, String OU, String O,
            String L, String S, String C) throws Exception {
        // generate PKCS10 certificate request
        String sigAlg = "MD5WithRSA";
        PKCS10 pkcs10 = new PKCS10(publicKey);
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        // common, orgUnit, org, locality, state, country
        X500Principal principal = new X500Principal( "CN=Ole Nordmann, OU=ACME, O=Sales, C=NO");

//        PKCS10CertificationRequest kpGen = new PKCS10CertificationRequest(sigAlg, principal, publicKey, null, privateKey);  
//        byte[] c = kpGen.getEncoded();
        X500Name x500name=null;
        x500name= new X500Name(principal.getEncoded());
      pkcs10.encodeAndSign(x500name, signature);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        byte[] c = bs.toByteArray();
        try {
            if (ps != null)
                ps.close();
            if (bs != null)
                bs.close();
        } catch (Throwable th) {
        }
        return c;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static void main(String[] args) throws Exception {
        GenerateCSR gcsr = GenerateCSR.getInstance();

        System.out.println("Public Key:\n"+gcsr.getPublicKey().toString());

        System.out.println("Private Key:\n"+gcsr.getPrivateKey().toString());
        String csr = gcsr.getCSR("journaldev.com <http://www.journaldev.com>");
        System.out.println("CSR Request Generated!!");
        System.out.println(csr);
    }

    
    
    private static final String SIGNATURE_ALGORITHM = "SHA1WITHRSA";
    private static final long VALIDITY_DAYS = 14L;


    @SuppressWarnings("restriction")
	public static byte[] sign(PKCS10 csr, X509CertImpl signerCert, PrivateKey signerPrivKey) throws CertificateException, IOException, InvalidKeyException, SignatureException {

        /*
         * The code below is partly taken from the KeyTool class in OpenJDK7.
         */

        X509CertInfo signerCertInfo = (X509CertInfo) signerCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
        X500Name issuer = (X500Name) signerCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateSubjectName.DN_NAME);

        /*
         * Set the certificate's validity:
         * From now and for VALIDITY_DAYS days 
         */
        Date firstDate = new Date();
        Date lastDate = new Date();
        lastDate.setTime(firstDate.getTime() + VALIDITY_DAYS * 1000L * 24L * 60L * 60L);
        CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

        /*
         * Initialize the signature object
         */
        Signature signature;
        try {
            signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        signature.initSign(signerPrivKey);

        /*
         * Add the certificate information to a container object
         */
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VALIDITY, interval);
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new Random().nextInt() & 0x7fffffff));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        try {
            certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(SIGNATURE_ALGORITHM)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(csr.getSubjectPublicKeyInfo()));
        certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(csr.getSubjectName()));

        /*
         * Add x509v3 extensions to the container
         */
        CertificateExtensions extensions = new CertificateExtensions();

        // Example extension.
        // See KeyTool source for more.
        boolean[] keyUsagePolicies = new boolean[9];
        keyUsagePolicies[0] = true; // Digital Signature
        keyUsagePolicies[2] = true; // Key encipherment
        KeyUsageExtension kue = new KeyUsageExtension(keyUsagePolicies);
        byte[] keyUsageValue = new DerValue(DerValue.tag_OctetString, kue.getExtensionValue()).toByteArray();
        extensions.set(KeyUsageExtension.NAME, new Extension(
                kue.getExtensionId(),
                true, // Critical
                keyUsageValue));
        /*
         * Create the certificate and sign it
         */
        X509CertImpl cert = new X509CertImpl(certInfo);
        try {
            cert.sign(signerPrivKey, SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        /*
         * Return the signed certificate as PEM-encoded bytes
         */
        ByteOutputStream bos = new ByteOutputStream();
        PrintStream out = new PrintStream(bos);
        BASE64Encoder encoder = new BASE64Encoder();
        out.println(X509Factory.BEGIN_CERT);
        encoder.encodeBuffer(cert.getEncoded(), out);
        out.println(X509Factory.END_CERT);
        out.flush();
        return bos.getBytes();
    }
    /**
     * converted to PEM
     * @param signedCertificate
     * @return
     * @throws IOException
     */
    /*private String convertCertificateToPEM(X509Certificate signedCertificate) throws IOException {
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(signedCertificate);
        pemWriter.close();
       System.out.println("PEM data:");
        System.out.println("" + signedCertificatePEMDataStringWriter.toString());
        return signedCertificatePEMDataStringWriter.toString();
      }*/
}