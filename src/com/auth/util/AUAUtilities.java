/*
 * 
 */
package com.auth.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.crypto.CryptoException;

// TODO: Auto-generated Javadoc
/**
 * The Class AUAUtilities.
 */
public class AUAUtilities {

	private final static String TRANSFORMATION = "AES";

	/**
	 * * Getting IP Address.
	 *
	 * @param request
	 *            the request
	 * @return the client ip addr
	 */

	public static String getClientIpAddr(HttpServletRequest request) {
		String ip = request.getHeader("X-Forwarded-For");
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("Proxy-Client-IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("WL-Proxy-Client-IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_X_FORWARDED_FOR");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_X_FORWARDED");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_X_CLUSTER_CLIENT_IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_CLIENT_IP");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_FORWARDED_FOR");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_FORWARDED");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("HTTP_VIA");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getHeader("REMOTE_ADDR");
		}
		if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
			ip = request.getRemoteAddr();
		}
		return ip;
	}

	/**
	 * *** generated the unique id .
	 *
	 * @return the int
	 */
	public static BigInteger generateUniqueId() {

		int randomPIN = (int) (Math.random() * 9000) + 1000;
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddhhmmssSSS");
		String txn = "" + randomPIN + dateFormat.format(new Date());
		BigInteger number = new BigInteger(txn);
		return number;

	}

	/**
	 * * Generated The Unique Id For BioMatric Request *.
	 *
	 * @return the int
	 */

	public static int biogenerateUniqueId() {
		UUID idBioOne = UUID.randomUUID();
		String strbio = "" + idBioOne;
		int uid = strbio.hashCode();
		String filterbioStr = "" + uid;
		strbio = filterbioStr.replaceAll("-", "");
		return Integer.parseInt(strbio);
	}

	public static String doDecrypt(String encodekey, String encrptedStr) {
		try {

			Cipher dcipher = Cipher.getInstance(TRANSFORMATION);
			byte[] key = encodekey.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-512");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			dcipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] dec = Base64.getDecoder().decode(encrptedStr.getBytes());
			byte[] utf8 = dcipher.doFinal(dec);

			// create new string based on the specified charset
			return new String(utf8, "UTF8");

		} catch (BadPaddingException e) {
			return "A900";
		} catch (Exception e) {

			return "A900";

		}

	}

	public static String doEncrypt(String encodekey, String inputStr) throws CryptoException {
		try {

			// getting cipher object of AES Tranforamation
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			byte[] key = encodekey.getBytes("UTF-8");
			MessageDigest sha256hash = MessageDigest.getInstance("SHA-512");

			// this is important to copy only first 128 bit of key, this must be
			// done by decryption process also.
			key = sha256hash.digest(key);
			key = Arrays.copyOf(key, 16);

			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

			byte[] inputBytes = inputStr.getBytes();
			byte[] outputBytes = cipher.doFinal(inputBytes);

			//System.out.println("outputBytes" + outputBytes);

			return new String(Base64.getEncoder().encode(outputBytes));

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException | IOException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}

}
