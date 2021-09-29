package cert.generate_type4;

import java.security.cert.X509Certificate;

import cert.validator.CertChainValidator;

public class Main {

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
//        if (null!=rootCa) {
//        	System.out.println("rootCA genarate success");
        	boolean st = CertChainValidator.checkCert(rootParam.getCaKeyStorePath(), rootParam.getCaKeyStorePwd(), rootParam.getCaPath());
        	if (st) {
       		 System.out.println("rootCA validate success");
			}else {
				System.out.println("rootCA validate fail");
			}
//		}
//        if (null!=childCa) {
//        	System.out.println("childCA genarate success");
        	boolean st2 = CertChainValidator.checkCert(rootParam.getCaKeyStorePath(), rootParam.getCaKeyStorePwd(), childParam.getCaPath());
        	if (st2) {
        		 System.out.println("child validate success");
			}else {
				System.out.println("child validate fail");
			}
//        }
	}

}
