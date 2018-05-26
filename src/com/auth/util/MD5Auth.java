/*
 * 
 */
package com.auth.util;

import java.security.MessageDigest;    
import sun.misc.BASE64Encoder;


// TODO: Auto-generated Javadoc
/**
 * The Class MD5Auth.
 */
public class MD5Auth {

	
	/**
	 * Encode.
	 *
	 * @param in the in
	 * @return the string
	 * @throws Exception the exception
	 */
	public String encode(String in) throws Exception {
	    
		  String generatedPassword = null;
	    try {
	    	MessageDigest md = MessageDigest.getInstance("MD5");
	        //Add password bytes to digest
	        md.update(in.getBytes());
	        //Get the hash's bytes 
	        byte[] bytes = md.digest();
	        //This bytes[] has bytes in decimal format;
	        //Convert it to hexadecimal format
	        StringBuilder sb = new StringBuilder();
	        for(int i=0; i< bytes.length ;i++)
	        {
	            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
	        }
	        //Get complete hashed password in hex format
	        return generatedPassword = sb.toString();
	    } catch (Exception se) {
	      throw new Exception("Exception while encoding " + se);
	    }

	  }

	  /**
  	 * Decode.
  	 *
  	 * @param in the in
  	 * @return the string
  	 */
  	public String decode(String in) {
	    throw new RuntimeException("NOT SUPPORTED");
	  }
	
	
}
