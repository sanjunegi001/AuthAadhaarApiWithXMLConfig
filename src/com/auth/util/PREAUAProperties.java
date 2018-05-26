package com.auth.util;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

public class PREAUAProperties {


	
	/*The GEO FILE
	 * */
	public static String geofile;
	
	/*The LOG PATH
	 * */
	public static String logPath;
	
	/*The CLIENT ID
	 * */
	public static String client_id;
	
	/*The CLIENT PFX
	 * */
	public static String client_pfx;
	
	/*The CLIENT PASS
	 * */
	public static String client_password;
	
	/*The UIDAI SIGNING CERT
	 * */
	public static String uidai_signing_cert;
	
	/*The UIDAI ENCRYPT CERT
	 * */
	public static String uidai_encrypt_cert;
	
	/*The UIDAI  AUA CODE
	 * */
	public static String uidai_aua_code;
	
	/*The UIDAI SUB AUA CODE
	 * */
	public static String uidai_subaua_code;
	
	/*The UIDAI LICENSE KEY
	 * */
	public static String uidai_license_key;
	
	public static String uidai_bio_license_key;
	
	/*The ASA URL
	 * */
	public static String asa_request_url;
	
	
	public static void load()
	{
	    Properties properties = new Properties();
	    try
	    {
	      
	    	try
	    	{
	    		
	    		
	    		ClassLoader classloader = Thread.currentThread().getContextClassLoader();
	    		properties.load(new FileInputStream(new File(classloader.getResource("pre-aua.properties").getFile())));
	    	   
	    		if (properties.getProperty("geofile") != null) {
	    			geofile=properties.getProperty("geofile").toString();
				}
	    		
	    		if (properties.getProperty("logPath") != null) {
	    			logPath=properties.getProperty("logPath").toString();
				}
	    		
	    		if (properties.getProperty("client_id") != null) {
	    			client_id=properties.getProperty("client_id").toString();
				}
	    		
	    		if (properties.getProperty("client_pfx") != null) {
	    			client_pfx=properties.getProperty("client_pfx").toString();
				}
	    		
	    		if (properties.getProperty("client_password") != null) {
	    			client_password=properties.getProperty("client_password").toString();
				}
	    		
	    		if (properties.getProperty("uidai_signing_cert") != null) {
	    			uidai_signing_cert=properties.getProperty("uidai_signing_cert").toString();
				}
	    		
	    		if (properties.getProperty("uidai_encrypt_cert") != null) {
	    			uidai_encrypt_cert=properties.getProperty("uidai_encrypt_cert").toString();
				}
	    		
	    		if (properties.getProperty("uidai_aua_code") != null) {
	    			uidai_aua_code=properties.getProperty("uidai_aua_code").toString();
				}
	    		
	    		if (properties.getProperty("uidai_subaua_code") != null) {
	    			uidai_subaua_code=properties.getProperty("uidai_subaua_code").toString();
				}
	    		
	    		if (properties.getProperty("uidai_license_key") != null) {
	    			uidai_license_key=properties.getProperty("uidai_license_key").toString();
				}
	    		
	    		if (properties.getProperty("uidai_bio_license_key") != null) {
					uidai_bio_license_key = properties.getProperty("uidai_bio_license_key").toString();
				}
	    		
	    		if (properties.getProperty("asa_request_url") != null) {
	    			asa_request_url=properties.getProperty("asa_request_url").toString();
				}
	    			    		
	    	
	    	}
	    	catch(Exception e)
	    	{
	    		System.out.println("loadexcption:::"+e);
	    	}
	  
            
	    }
	    catch (Exception e)
	    {
	    	e.printStackTrace();
	    	System.out.println("Unable to load properties"+e);
	    }
	}


	public static String getGeofile() {
		return geofile;
	}


	public static void setGeofile(String geofile) {
		PREAUAProperties.geofile = geofile;
	}


	public static String getLogPath() {
		return logPath;
	}


	public static void setLogPath(String logPath) {
		PREAUAProperties.logPath = logPath;
	}


	public static String getClient_id() {
		return client_id;
	}


	public static void setClient_id(String client_id) {
		PREAUAProperties.client_id = client_id;
	}


	public static String getClient_pfx() {
		return client_pfx;
	}


	public static void setClient_pfx(String client_pfx) {
		PREAUAProperties.client_pfx = client_pfx;
	}


	public static String getClient_password() {
		return client_password;
	}


	public static void setClient_password(String client_password) {
		PREAUAProperties.client_password = client_password;
	}


	public static String getUidai_signing_cert() {
		return uidai_signing_cert;
	}


	public static void setUidai_signing_cert(String uidai_signing_cert) {
		PREAUAProperties.uidai_signing_cert = uidai_signing_cert;
	}


	public static String getUidai_encrypt_cert() {
		return uidai_encrypt_cert;
	}


	public static void setUidai_encrypt_cert(String uidai_encrypt_cert) {
		PREAUAProperties.uidai_encrypt_cert = uidai_encrypt_cert;
	}


	public static String getUidai_aua_code() {
		return uidai_aua_code;
	}


	public static void setUidai_aua_code(String uidai_aua_code) {
		PREAUAProperties.uidai_aua_code = uidai_aua_code;
	}


	public static String getUidai_subaua_code() {
		return uidai_subaua_code;
	}


	public static void setUidai_subaua_code(String uidai_subaua_code) {
		PREAUAProperties.uidai_subaua_code = uidai_subaua_code;
	}


	public static String getUidai_license_key() {
		return uidai_license_key;
	}


	public static void setUidai_license_key(String uidai_license_key) {
		PREAUAProperties.uidai_license_key = uidai_license_key;
	}


	
	
	public static String getUidai_bio_license_key() {
		return uidai_bio_license_key;
	}


	public static void setUidai_bio_license_key(String uidai_bio_license_key) {
		PREAUAProperties.uidai_bio_license_key = uidai_bio_license_key;
	}


	public static String getAsa_request_url() {
		return asa_request_url;
	}


	public static void setAsa_request_url(String asa_request_url) {
		PREAUAProperties.asa_request_url = asa_request_url;
	}
	
	public static byte[] readAll(String filename) throws Exception {
		File file = new File(filename);
		int length = (int) file.length();

		byte[] data = new byte[length];
		FileInputStream fis = new FileInputStream(file);
		fis.read(data);
		fis.close();

		return data;
	}
	
}
