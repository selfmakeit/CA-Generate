package cert.sign2file;

import cert.generate_type1.CertificateUtils;
import cert.generate_type3.CertificateGenerationUtil;



public class Main {

	public static void main(String[] args) throws Exception {
		
		String alias = "childCA";
		String pwd = "123456";
//		String ksPath = "G:/exportCert/test.jks";
//		String ctPath = "G:/exportCert/test.cer";
		String ksPath = "f:\\GenX509Cert\\childCa.pfx";
		String ctPath = "F:\\GenX509Cert\\childCa.crt";
//		boolean res = CertificateGenerationUtil.generate("www.hwadee.com", "hwadee", "cqlcb", "chengdu", 
//				"sichuan", "china",alias, pwd, ksPath, ctPath, 10);
//		if (res) {
//			System.out.println("generate ok");
//		}
			//展示证书信息
			CertificateGenerationUtil.loadAndDisplayChain(alias,pwd.toCharArray(), ksPath);
			
			//利用证书给文件签名
			String filePath = "G:\\W.txt";
	        String sign = "VXeTzh9M9THjW97NCxLs67pk7NRAOhuJLkgkbq/Z0IpeuZ00jpNBi9srDOikxQ05/Ego3n30EsxVh36Qq/vEFRtN1TTrSNPwvYlDkmAqKlOyeNaOF79/QJa2xBdl1YwLGcujwBVRjWymD++0ONshsDpZtwDVqB81AH2hKrOFxT0=";
//	        String sign = CertificateUtils.signFileToBase64(filePath, ksPath, alias, pwd);
	        System.err.println("签名：\r\n" + sign);
	        boolean result = CertificateUtils.verifyFileSign(filePath, sign, ctPath);
	        System.err.println("校验结果：" + result);
			
	}

}
