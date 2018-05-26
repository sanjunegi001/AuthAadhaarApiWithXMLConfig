package com.auth.util;
/*
 * 
 */

import java.io.IOException;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jdom.Document;
import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;

import com.sun.xml.internal.bind.v2.model.core.ErrorHandler;
import com.sun.xml.internal.bind.v2.runtime.IllegalAnnotationException;

import jdk.internal.org.xml.sax.SAXException;
import jdk.internal.org.xml.sax.SAXParseException;

// TODO: Auto-generated Javadoc
/**
 * The Class Util.
 */
public class Util {

	public boolean isValidPin(String pinco) {

		if (pinco.length() > 0) {
			Pattern pinc = Pattern.compile("^\\d{6}$");
			Matcher pincMatcher;
			pincMatcher = pinc.matcher(pinco.trim());

			System.out.println("PID" + pinco);

			if (pinco.trim().length() == 6 && pincMatcher.matches()) {
				return true;
			} else {

				return false;
			}
		} else {
			return false;
		}

	}

	/**
	 * Generate captcha text method 1.
	 *
	 * @return the string
	 */
	public static String generateCaptchaTextMethod1() {

		Random rdm = new Random();
		int rl = rdm.nextInt(); // Random numbers are generated.
		String hash1 = Integer.toHexString(rl); // Random numbers are converted
												// to Hexa Decimal.

		return hash1;

	}

	/**
	 * Generate captcha text method 2.
	 *
	 * @param captchaLength
	 *            the captcha length
	 * @return the string
	 */
	public static String generateCaptchaTextMethod2(int captchaLength) {

		String saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
		StringBuffer captchaStrBuffer = new StringBuffer();
		java.util.Random rnd = new java.util.Random();

		while (captchaStrBuffer.length() < captchaLength) {
			int index = (int) (rnd.nextFloat() * saltChars.length());
			captchaStrBuffer.append(saltChars.substring(index, index + 1));
		}

		return captchaStrBuffer.toString();

	}

	public static String maskCardNumber(String cardNumber) {

		// format the number
		String mask = "xxxxxxxx####";
		int index = 0;
		StringBuilder maskedNumber = new StringBuilder();
		for (int i = 0; i < mask.length(); i++) {
			char c = mask.charAt(i);
			if (c == '#') {
				maskedNumber.append(cardNumber.charAt(index));
				index++;
			} else if (c == 'x') {
				maskedNumber.append(c);
				index++;
			} else {
				maskedNumber.append(c);
			}
		}

		// return the masked number
		return maskedNumber.toString();
	}

	public boolean validarXML(String xml) throws ParserConfigurationException, org.xml.sax.SAXException, IOException, NullPointerException {

		System.out.println("dfd");
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);

		DocumentBuilder builder = factory.newDocumentBuilder();

		// builder.setErrorHandler(new SimpleErrorHandler());
		// the "parse" method also validates XML, will throw an exception if misformatted

		try {
			Document document = (Document) builder.parse(xml);
			org.jsoup.nodes.Document doc = Jsoup.parse(xml, "", Parser.xmlParser());
			System.out.println("sanjay" + doc.getElementsByTag("DeviceInfo").attr("dc").trim());

		} catch (Exception e) {
			System.out.println("dfdfdf" + e.getMessage());
			return false;
		}

		return true;
	}

	public class SimpleErrorHandler implements ErrorHandler, org.xml.sax.ErrorHandler {
		public void warning(SAXParseException e) throws SAXException {
			System.out.println("a1" + e.getMessage());
		}

		public void error(SAXParseException e) throws SAXException {
			System.out.println("a2" + e.getMessage());
		}

		public void fatalError(SAXParseException e) throws SAXException {
			System.out.println("a3" + e.getMessage());
		}

		@Override
		public void error(IllegalAnnotationException arg0) {
			// TODO Auto-generated method stub
			System.out.println("a4" + arg0.getMessage());

		}

		@Override
		public void error(org.xml.sax.SAXParseException arg0) throws org.xml.sax.SAXException {
			// TODO Auto-generated method stub
			System.out.println("a5" + arg0.getMessage());
		}

		public void error(Exception arg0) throws Exception {
			// TODO Auto-generated method stub
			System.out.println("a5" + arg0.getMessage());
		}

		@Override
		public void fatalError(org.xml.sax.SAXParseException arg0) throws org.xml.sax.SAXException {
			// TODO Auto-generated method stub
			System.out.println("a6" + arg0.getMessage());
		}

		@Override
		public void warning(org.xml.sax.SAXParseException arg0) throws org.xml.sax.SAXException {
			// TODO Auto-generated method stub
			System.out.println("a7" + arg0.getMessage());
		}
	}

}