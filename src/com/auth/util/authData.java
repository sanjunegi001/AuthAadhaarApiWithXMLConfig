package com.auth.util;

import org.apache.commons.lang.StringUtils;

import com.ecs.aua.pidgen.support.DemoAuthData;
import com.ecs.aua.pidgen.support.DemoAuthData.PiDateOfBirthType;
import com.ecs.aua.pidgen.support.DemoAuthData.PiGender;
import com.ecs.aua.pidgen.support.DemoAuthData.PiMatchingStrategy;

public class authData {

	public DemoAuthData authDataBlock = new DemoAuthData();

	public DemoAuthData setValueAt(String key, String val) {

		switch (key) {
		case "piValue":
			if (val.contentEquals("true")) {
				authDataBlock.getPersonalIdentity().setUsePi(Boolean.valueOf(val));
			}
			break;
		case "paValue":
			if (val.contentEquals("true")) {
				authDataBlock.getPersonalAddress().setUsePa(Boolean.valueOf(val));
				System.out.println("paOuter");
			}
			break;
		case "pfaValue":
			if (val.contentEquals("true")) {
				authDataBlock.getPersonalFullAddress().setUsePfa(Boolean.valueOf(val));
				System.out.println("pfaOuter");
			}
			break;
		case "aadhaar_name":
			authDataBlock.getPersonalIdentity().setName(val);
			authDataBlock.getPersonalIdentity().setMatchingStrategy(PiMatchingStrategy.E);
			authDataBlock.getPersonalFullAddress().setMatchingValue(Integer.parseInt("100"));
			break;

		case "dob":

			if (StringUtils.isNotEmpty(val)) {
				authDataBlock.getPersonalIdentity().setDateOfBirth(val);
				break;
			}

		case "dob_type":

			System.out.println("dob_type" + val);
			if (val.equalsIgnoreCase("D")) {
				System.out.println("dob_type1" + val);
				authDataBlock.getPersonalIdentity().setDateOfBirthType(PiDateOfBirthType.D);
			} else if (val.equalsIgnoreCase("A")) {
				System.out.println("dob_type2" + val);
				authDataBlock.getPersonalIdentity().setDateOfBirthType(PiDateOfBirthType.A);
			}

			else if (val.equalsIgnoreCase("V")) {
				System.out.println("dob_type3" + val);
				authDataBlock.getPersonalIdentity().setDateOfBirthType(PiDateOfBirthType.V);
			}

			// else {
			//
			// System.out.println(x);
			// authDataBlock.getPersonalIdentity().setDateOfBirthType(PiDateOfBirthType.NONE);
			// }

			break;

		case "gender":

			if (val.equalsIgnoreCase("M")) {
				authDataBlock.getPersonalIdentity().setGender(PiGender.M);
			} else if (val.equalsIgnoreCase("T")) {
				authDataBlock.getPersonalIdentity().setGender(PiGender.T);
			} else if (val.equalsIgnoreCase("F")) {
				authDataBlock.getPersonalIdentity().setGender(PiGender.F);
			} else {
				authDataBlock.getPersonalIdentity().setGender(PiGender.NONE);
			}
			break;
		case "email":

			authDataBlock.getPersonalIdentity().seteMail(val);
			break;
		case "mobileno":
			authDataBlock.getPersonalIdentity().setPhone(val);
			System.out.println("authData mobileno" + val);
			break;
		case "careof":
			authDataBlock.getPersonalAddress().setCareOf(val);
			System.out.println("careof" + key + " " + val);
			break;
		case "building":
			authDataBlock.getPersonalAddress().setHouse(val);
			System.out.println("building" + key + " " + val);
			break;
		case "landmark":
			authDataBlock.getPersonalAddress().setLandmark(val);
			System.out.println("landmark" + key + " " + val);
			break;
		case "street":
			authDataBlock.getPersonalAddress().setStreet(val);
			System.out.println("street" + key + " " + val);
			break;
		case "locality":
			authDataBlock.getPersonalAddress().setLocality(val);
			System.out.println("locality" + key + " " + val);
			break;
		case "poname":
			authDataBlock.getPersonalAddress().setPostOffice(val);
			System.out.println("poname" + key + " " + val);
			break;
		case "vtc":
			authDataBlock.getPersonalAddress().setVillageTownCity(val);
			System.out.println("vtc" + key + " " + val);
			break;
		case "subdist":
			authDataBlock.getPersonalAddress().setSubDistrict(val);
			System.out.println("subdist" + key + " " + val);
			break;
		case "dist":
			authDataBlock.getPersonalAddress().setDistrict(val);
			System.out.println("dist" + key + " " + val);
			break;
		case "state":
			authDataBlock.getPersonalAddress().setState(val);
			System.out.println("state" + key + " " + val);
			break;

		case "pincode":
			authDataBlock.getPersonalAddress().setPincode(val);
			System.out.println("pincode" + key + " " + val);
			break;

		case "faddress":
			authDataBlock.getPersonalFullAddress().setAddress(val);
			System.out.println("faddress" + key + " " + val);
			break;

		}

		return authDataBlock;

	}

}
