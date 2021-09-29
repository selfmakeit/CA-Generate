package cert.sign2file;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CertificateTester {

//    private static final String KEY_STORE_NAME = "cqlcb.keystore";
    private static final String KEY_STORE_NAME = "aaa.jks";
    private static final String CERTIFICATE_NAME = "aaa.cer";
    private static final String password = "123456";
    private static final String alias = "mykey";
    private static String certificatePath;
    private static String keyStorePath;
   
    static {
        String currentDir = CertificateTester.class.getResource("").getPath();
        if (currentDir.startsWith("/"))
            currentDir = currentDir.substring(1);
        if (!currentDir.endsWith("/"))
            currentDir += "/";
        keyStorePath = currentDir + KEY_STORE_NAME;
        certificatePath = currentDir + CERTIFICATE_NAME;
    }
    public static void main(String[] args) throws Exception {
//        simple();
//        simpleSign();
        testFileSign();
    }
    static void simple() throws Exception {
        System.err.println("公钥加密——私钥解密");
        String source = "这是一行没有任何意义的文字，你看完了等于没看，不是吗？";
        byte[] data = source.getBytes();
        byte[] encrypt = CertificateUtils.encryptByPublicKey(data, certificatePath);
        byte[] decrypt = CertificateUtils.decryptByPrivateKey(encrypt, keyStorePath, alias, password);
        String outputStr = new String(decrypt);
        System.out.println("加密前: \r\n" + source + "\r\n" + "解密后: \r\n" + outputStr);
        // 验证数据一致
        assertArrayEquals(data, decrypt);
        // 验证证书有效
        assertTrue(CertificateUtils.verifyCertificate(certificatePath));
    }

    static void simpleSign() throws Exception {
        System.err.println("私钥加密——公钥解密");

        String source = "这是一行签名的测试文字";
        byte[] data = source.getBytes();

        byte[] encodedData = CertificateUtils.encryptByPrivateKey(data, keyStorePath, alias, password);

        byte[] decodedData = CertificateUtils.decryptByPublicKey(encodedData, certificatePath);

        String target = new String(decodedData);
        System.out.println("加密前: \r\n" + source + "\r\n" + "解密后: \r\n" + target);
        assertEquals(source, target);

        System.err.println("私钥签名——公钥验证签名");
        // 产生签名
        String sign = CertificateUtils.signToBase64(encodedData, keyStorePath, alias, password);
        System.out.println("签名:\r\n" + sign);

        // 验证签名
        boolean status = CertificateUtils.verifySign(encodedData, sign, certificatePath);
        System.err.println("状态:\r\n" + status);
        assertTrue(status);
    }
   
    @SuppressWarnings("deprecation")
	static void testFileSign() throws Exception {
        String filePath = "G:\\aa.txt";
//        String sign = "KQ3pwtl3WwGchhKLnLOiY2sMkPZRIRPaBv9Y08TPdirh1nYccJxiV6PV7N8vaQVQIfQ6RxwWiFWel60fWme94yWzvGnz8/C+5f3GIG3h4SWmOAEnf45SLECaDZwCGeqYKTd2ah7mENvsycMQouY1bC/9kHT+ZEDDvDva/6lmyJWE9lc0whzMNlLaT/NXgaL174P/qCTIdg9AHuSeTjWmun9lW33VRYQsZBLketaIDvNjb0lE9X5n5zvaQDIoUWRzSa0MgQ5X4KF2YT3P0s1QkI9rh2d2wfzSH2PYLWT3TlNMmntv85H4tpYNwsns77kevM4JrWCbf8MkJ7tIdc7Ekw==";
        String sign = CertificateUtils.signFileToBase64(filePath, keyStorePath, alias, password);
        System.err.println("生成签名：\r\n" + sign);
        boolean result = CertificateUtils.verifyFileSign(filePath, sign, certificatePath);
        System.err.println("校验结果：" + result);
    }
   
}
