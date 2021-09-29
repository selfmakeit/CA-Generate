package cert.generate_type4;

public class CertParamEntity {

	private CertParamEntity parentCa;
	private String dnName;
	private int validDay;
	private String caPath;
	private String caKeyStorePath;
	private String caKeyStorePwd;
	private String caAlias;
	private String caPublicKeyPath;
	private String caprivateKeyPath;
	public CertParamEntity getParentCa() {
		return parentCa;
	}
	public void setParentCa(CertParamEntity parentCa) {
		this.parentCa = parentCa;
	}
	public String getDnName() {
		return dnName;
	}
	public void setDnName(String dnName) {
		this.dnName = dnName;
	}
	public int getValidDay() {
		return validDay;
	}
	public void setValidDay(int validDay) {
		this.validDay = validDay;
	}
	public String getCaPath() {
		return caPath;
	}
	public void setCaPath(String caPath) {
		this.caPath = caPath;
	}
	public String getCaKeyStorePath() {
		return caKeyStorePath;
	}
	public void setCaKeyStorePath(String caKeyStorePath) {
		this.caKeyStorePath = caKeyStorePath;
	}
	public String getCaKeyStorePwd() {
		return caKeyStorePwd;
	}
	public void setCaKeyStorePwd(String caKeyStorePwd) {
		this.caKeyStorePwd = caKeyStorePwd;
	}
	public String getCaAlias() {
		return caAlias;
	}
	public void setCaAlias(String caAlias) {
		this.caAlias = caAlias;
	}
	public String getCaPublicKeyPath() {
		return caPublicKeyPath;
	}
	public void setCaPublicKeyPath(String caPublicKeyPath) {
		this.caPublicKeyPath = caPublicKeyPath;
	}
	public String getCaprivateKeyPath() {
		return caprivateKeyPath;
	}
	public void setCaprivateKeyPath(String caprivateKeyPath) {
		this.caprivateKeyPath = caprivateKeyPath;
	}
	
}
