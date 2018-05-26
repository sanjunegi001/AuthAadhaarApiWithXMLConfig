package com.auth.util;

import java.io.IOException;

import sun.misc.BASE64Decoder;

public class IpassCustomBase64 {

	public String decode(String base64String) {

		String encodedString = "";

		BASE64Decoder decoder = new BASE64Decoder();
		byte[] ipassdata;
		try {
			
			ipassdata = decoder.decodeBuffer(base64String.trim());
			encodedString = new String(ipassdata, "UTF-8");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		
		return encodedString;

	}

}
