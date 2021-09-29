package cert.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * @desc pfx格式和keystore格式的证书互转
 *  jks(java key store)：
	java用的存储密钥的容器。可以同时容纳n个公钥或私钥，后缀一般是.jks或者.keystore或.truststore等，千奇百怪。
	不管什么后缀，它就是一个容器，各个公司或机构叫法不同而已。比如把只包含"受信任的公钥"的容器存成.truststore文件等。
	用jdk\bin目录下的keytool.exe对其进行查看，导入，导出，删除，修改密码等各种操作。可以对jks容器加密码，
	输入正确才可以操作此容器中密钥。还有一个密码的概念与上者不同，是jks中存储着的私钥的密码，通常是绝密的。
	pfx：
	和jks功能相同但文件格式不同，pfx是浏览器用的。
	可以用一些工具程序把pfx转化成jks格式供java程序使用(如银行只提供了pfx，但是我们想用httpclient模拟浏览器自动访问时)。
	据说IE导出的pfx格式不标准，转化jks时往往报错，可以尝试用Netscape Navigator导入再导出，然后再转化。碰到过这样的情况。
 */

public class ConvertPFXToKeystoreUtil {
	public static final String PKCS12 = "PKCS12";
	public static final String JKS = "JKS";
	public static final String PFX_KEYSTORE_FILE = "f:\\GenX509Cert\\ScriptX.pfx";
	public static final String KEYSTORE_PASSWORD = "123456";
	public static final String JKS_KEYSTORE_FILE = "G:\\bycx.keystore";

	/**
	 * 将pfx或p12的文件转为keystore
	 */
	public static void coverTokeyStore() {
		try {
			KeyStore inputKeyStore = KeyStore.getInstance("PKCS12");
			FileInputStream fis = new FileInputStream(PFX_KEYSTORE_FILE);
			char[] nPassword = null;

			if ((KEYSTORE_PASSWORD == null)
					|| KEYSTORE_PASSWORD.trim().equals("")) {
				nPassword = null;
			} else {
				nPassword = KEYSTORE_PASSWORD.toCharArray();
			}

			inputKeyStore.load(fis, nPassword);
			fis.close();

			KeyStore outputKeyStore = KeyStore.getInstance("JKS");

			outputKeyStore.load(null, KEYSTORE_PASSWORD.toCharArray());

			Enumeration enums = inputKeyStore.aliases();

			while (enums.hasMoreElements()) { // we are readin just one
				// certificate.

				String keyAlias = (String) enums.nextElement();

				System.out.println("alias=[" + keyAlias + "]");

				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, nPassword);
					Certificate[] certChain = inputKeyStore
							.getCertificateChain(keyAlias);

					outputKeyStore.setKeyEntry(keyAlias, key,
							KEYSTORE_PASSWORD.toCharArray(), certChain);
				}
			}

			FileOutputStream out = new FileOutputStream(JKS_KEYSTORE_FILE);

			outputKeyStore.store(out, nPassword);
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 将keystore转为pfx
	 */
	public static void coverToPfx() {
		try {
			KeyStore inputKeyStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(JKS_KEYSTORE_FILE);
			char[] nPassword = null;

			if ((KEYSTORE_PASSWORD == null)
					|| KEYSTORE_PASSWORD.trim().equals("")) {
				nPassword = null;
			} else {
				nPassword = KEYSTORE_PASSWORD.toCharArray();
			}

			inputKeyStore.load(fis, nPassword);
			fis.close();

			KeyStore outputKeyStore = KeyStore.getInstance("PKCS12");

			outputKeyStore.load(null, KEYSTORE_PASSWORD.toCharArray());

			Enumeration enums = inputKeyStore.aliases();

			while (enums.hasMoreElements()) { // we are readin just one
				// certificate.

				String keyAlias = (String) enums.nextElement();

				System.out.println("alias=[" + keyAlias + "]");

				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, nPassword);
					Certificate[] certChain = inputKeyStore
							.getCertificateChain(keyAlias);

					outputKeyStore.setKeyEntry(keyAlias, key,
							KEYSTORE_PASSWORD.toCharArray(), certChain);
				}
			}

			FileOutputStream out = new FileOutputStream(PFX_KEYSTORE_FILE);

			outputKeyStore.store(out, nPassword);
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		coverTokeyStore();
	}
}