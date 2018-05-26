package com.auth.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class paramValidation {

	public boolean isAaadharValid(String aadhaar) {
		Pattern p = Pattern.compile("^\\d{12}$");
		Matcher numberMatcher;
		boolean isAadhaar;
		numberMatcher = p.matcher(aadhaar);

		if (numberMatcher.matches()) {
			isAadhaar = true;
			return isAadhaar;
		} else {
			isAadhaar = false;
			return isAadhaar;
		}
	}

	public boolean isDobTypeValid(String dob_type) {
		boolean isdobtypeValid;
		if (dob_type.equalsIgnoreCase("V") || dob_type.equalsIgnoreCase("D") || dob_type.equalsIgnoreCase("A")) {
			isdobtypeValid = true;
			return isdobtypeValid;
		} else {
			isdobtypeValid = false;
			return isdobtypeValid;
		}
	}

	public boolean isgenderValid(String gender) {
		boolean isGender;
		if (gender.equalsIgnoreCase("M") || gender.equalsIgnoreCase("F") || gender.equalsIgnoreCase("T")) {

			isGender = true;
			return isGender;
		} else {
			isGender = false;
			return isGender;
		}
	}

	public boolean ismobileValid(String mobile) {
		boolean isMobile;
		Pattern pattern = Pattern.compile("^[0-9]{10}$");
		Matcher matcher = pattern.matcher(mobile);

		if (matcher.matches()) {
			isMobile = true;
			return isMobile;
		} else {
			isMobile = false;
			return isMobile;
		}
	}

	public boolean isemailValid(String Email) {
		boolean isEmail;
		Pattern epattern = Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@" + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");
		Matcher matcher = epattern.matcher(Email);
		if (matcher.matches()) {
			isEmail = true;
			return isEmail;
		} else {
			isEmail = false;
			return isEmail;
		}
	}

	public Boolean isValidRequest(String aadhaar) {
		// TODO Auto-generated method stub

		System.out.println("aadhaar" + aadhaar);

		return null;
	}

}
