package com.auth.controller;

import java.io.IOException;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.auth.bean.Personal;
import com.auth.bean.Residential;
import com.auth.bean.Verification;
import com.auth.dao.PersonalDAO;
import com.auth.dao.ResidentialDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.domain.User;
import com.auth.util.AUAUtilities;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
import com.ecs.asa.processor.AuthProcessor;
import com.ecs.asa.processor.AuthProcessor.RcType;
import com.ecs.asa.processor.AuthProcessor.TidType;
import com.ecs.asa.utils.HttpConnector;
import com.ecs.aua.pidgen.support.DemoAuthData;
import com.ecs.aua.pidgen.support.DemoAuthData.PfaMatchingStrategy;
import com.ecs.aua.pidgen.support.DemoAuthData.PiGender;
import com.ecs.aua.pidgen.support.DemoAuthData.PiMatchingStrategy;
import com.ecs.exceptions.AsaServerException;
import com.ecs.exceptions.InvalidResponseException;
import com.ecs.exceptions.UidaiSignatureVerificationFailedException;
import com.ecs.exceptions.XMLParsingException;
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;

//TODO: Auto-generated Javadoc
/**
 * Home Controller Demo AUTH.
 */
@Controller
public class HomeController {

	/** The finger print. */
	String asaResponseXML = null, fingerpostion = null, biotransactionid = null, errorcode = null, errordescription = null, txtAadhaarNo = null, fingerPrint = null;

	/** The user login DAO. */
	@Autowired
	private UserLoginDAO userLogindao;

	/** The verification DAO. */
	@Autowired
	private VerificationDAO verificationDAO;

	/** The personal DAO. */
	@Autowired
	private PersonalDAO personalDAO;

	/** The residential DAO. */
	@Autowired
	private ResidentialDAO residentialDAO;

	/**
	 * Home.
	 *
	 * @param user
	 *            the user
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/home", method = RequestMethod.GET)
	public ModelAndView Home(@ModelAttribute("user") User user, HttpSession session) throws Exception {

		String propFilePath = "";
		// AUAProperties.load(propFilePath);
		try {
			PREAUAProperties.load();
			int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));

			if (session.getAttribute("user_login_name") != null && access == 1) {
				return new ModelAndView("Home");
			} else {
				Log.aua.info("User Login Failed ::" + session.getAttribute("user_login_name"));
				return new ModelAndView("redirect:/login.html");

			}
		} catch (Exception e) {
			System.out.println(e);
			return new ModelAndView("redirect:/login.html");
		}

	}

	/**
	 * Demo Authentication *.
	 *
	 * @param user
	 *            the user
	 * @param model
	 *            the model
	 * @param request
	 *            the request
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/processAuthentication", method = { RequestMethod.POST, RequestMethod.GET })
	public @ResponseBody String processAuthentication(@ModelAttribute("user") User user, Model model, HttpServletRequest request, HttpSession session) throws Exception {

		PREAUAProperties.load();
		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
		boolean piValue = false;
		boolean paValue = false;
		boolean pfaValue = false;

		/***
		 * Check Operator Login Or Not
		 */
		Log.aua.info("CONSENT: CONSENT TAKEN BY USER");
		Log.aua.info("User Login For Demo Auth ::" + session.getAttribute("user_login_name"));

		if (session.getAttribute("user_login_name") != null && access == 1) {

			Date startTime = null;
			Calendar c1 = Calendar.getInstance();
			startTime = c1.getTime();
			Date connectionStartTime = null;

			/**
			 * Getting The Location Of Operator
			 **/
			String flocation = "", fpostalcode = "", fcity = "";
			String orgip = AUAUtilities.getClientIpAddr(request);

			String response_time = "", request_time = "", matchingvalue = "";
			String year = "";
			String month = "";
			String date = "";
			String dob = "";
			// System.out.println("negi:"+classLoader.getResource("GeoLiteCity.dat").getFile());
			String geofile = PREAUAProperties.getGeofile();
			LookupService lookUp = new LookupService(PREAUAProperties.getGeofile(), LookupService.GEOIP_MEMORY_CACHE);

			try {
				lookUp = new LookupService(PREAUAProperties.getGeofile(), LookupService.GEOIP_MEMORY_CACHE);

				Location location = lookUp.getLocation(orgip);

				if (location != null) {
					flocation = location.countryName;
					fpostalcode = location.postalCode;
					fcity = location.city;
				} else {
					flocation = "India";
					fpostalcode = "122015";
					fcity = "Gurgaon";
				}
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();

			}

			String aadharcardnumber = request.getParameter("aadhaar").trim();
			String uidname = request.getParameter("name").trim();

			String matchingstargey = request.getParameter("name_match").trim();
			String verify_name = session.getAttribute("user_login_name").toString();

			if (!request.getParameter("year").trim().equals("")) {
				year = request.getParameter("year").trim();

			}
			if (!request.getParameter("month").trim().equals("")) {
				month = request.getParameter("month").trim();

			}
			if (!request.getParameter("date").trim().equals("")) {
				date = request.getParameter("date").trim();

			}

			if (!year.equals("") || !month.equals("") || !date.equals("")) {

				dob = year + "-" + month + "-" + date.trim();
			}

			if (!year.equals("") && month.equals("") && date.equals("")) {

				dob = dob.replaceAll("\\--", "").trim();
			}

			String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();

			AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()), PREAUAProperties.readAll(PREAUAProperties.getUidai_signing_cert()));

			pro.setUid(aadharcardnumber);
			pro.setAc(PREAUAProperties.getUidai_aua_code());
			pro.setSa(PREAUAProperties.getUidai_subaua_code());
			pro.setRc(RcType.Y);
			pro.setTid(TidType.None);
			pro.setLk(PREAUAProperties.getUidai_license_key());
			pro.setTxn(utransactionId);

			DemoAuthData dd = new DemoAuthData();

			if ((request.getParameter("name").trim() != null && request.getParameter("name").trim().length() != 0) || (dob != null && dob.length() != 0) || (request.getParameter("gender").trim() != null && request.getParameter("gender").length() != 0 || (request.getParameter("email").trim() != null && request.getParameter("email").length() != 0) || (request.getParameter("mobileno").trim() != null && request.getParameter("mobileno").length() != 0))

			) {

				piValue = true;
				paValue = false;
				pfaValue = false;

				if (matchingstargey.contains("P")) {

					if (dob.equals("") && request.getParameter("gender").trim().equals("") && request.getParameter("email").trim().equals("") && request.getParameter("mobileno").trim().equals("")) {
						int matchValue = Integer.parseInt(request.getParameter("name_matchingvalue").trim());
						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().setName(uidname);
						dd.getPersonalIdentity().setMatchingStrategy(PiMatchingStrategy.P);
						dd.getPersonalIdentity().setMatchingValue(matchValue);
					} else if (!dob.equals("")) {
						int matchValue = Integer.parseInt(request.getParameter("name_matchingvalue").trim());
						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().setName(uidname);
						dd.getPersonalIdentity().setMatchingStrategy(PiMatchingStrategy.P);
						dd.getPersonalIdentity().setMatchingValue(matchValue);
						dd.getPersonalIdentity().setDateOfBirth(dob);
					} else if (!request.getParameter("gender").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						if (request.getParameter("gender").trim().equals("M"))
							dd.getPersonalIdentity().setGender(PiGender.M);
						else if (request.getParameter("gender").trim().equals("F"))
							dd.getPersonalIdentity().setGender(PiGender.F);
						else
							dd.getPersonalIdentity().setGender(PiGender.T);
					} else if (!request.getParameter("mobileno").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().setPhone(request.getParameter("mobileno").trim());

					} else if (!request.getParameter("email").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().seteMail(request.getParameter("email").trim());

					}

				} else {

					if (dob.equals("") && request.getParameter("gender").trim().equals("") && request.getParameter("email").trim().equals("") && request.getParameter("mobileno").trim().equals("")) {
						int matchValue = Integer.parseInt(request.getParameter("name_matchingvalue").trim());

						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().setName(uidname);
						dd.getPersonalIdentity().setMatchingStrategy(PiMatchingStrategy.E);
						dd.getPersonalIdentity().setMatchingValue(matchValue);
					} else if (!dob.equals("")) {
						int matchValue = Integer.parseInt(request.getParameter("name_matchingvalue").trim());

						dd.getPersonalIdentity().setUsePi(piValue);
						// dd.getPersonalIdentity().setName(uidname);
						// dd.getPersonalIdentity().setMatchingStrategy(PiMatchingStrategy.E);
						// dd.getPersonalIdentity().setMatchingValue(matchValue);
						// dd.getPersonalIdentity().setDateOfBirthType(PiDateOfBirthType.D);
						dd.getPersonalIdentity().setDateOfBirth(dob);

					} else if (!request.getParameter("gender").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						if (request.getParameter("gender").trim().equals("M"))
							dd.getPersonalIdentity().setGender(PiGender.M);
						else if (request.getParameter("gender").trim().equals("F"))
							dd.getPersonalIdentity().setGender(PiGender.F);
						else
							dd.getPersonalIdentity().setGender(PiGender.T);
					} else if (!request.getParameter("mobileno").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().setPhone(request.getParameter("mobileno").trim());

					} else if (!request.getParameter("email").trim().equals("")) {

						dd.getPersonalIdentity().setUsePi(piValue);
						dd.getPersonalIdentity().seteMail(request.getParameter("email").trim());

					}
				}

			} else if ((user.getStrAddressValue().trim() != null && user.getStrAddressValue().trim().length() != 0)) {

				piValue = false;
				paValue = false;
				pfaValue = true;

				if (request.getParameter("strPfaMatched").trim().contains("E")) {

					dd.getPersonalFullAddress().setUsePfa(pfaValue);
					dd.getPersonalFullAddress().setAddress(request.getParameter("strAddressValue"));
					dd.getPersonalFullAddress().setMatchingStrategy(PfaMatchingStrategy.E);
					dd.getPersonalFullAddress().setMatchingValue(100);

				} else if (request.getParameter("strPfaMatched").trim().contains("P")) {

					dd.getPersonalFullAddress().setUsePfa(pfaValue);
					dd.getPersonalFullAddress().setAddress(request.getParameter("strAddressValue"));
					dd.getPersonalFullAddress().setMatchingStrategy(PfaMatchingStrategy.P);
					dd.getPersonalFullAddress().setMatchingValue(Integer.parseInt(request.getParameter("strAddressMatchvalue").trim()));

				}

			} else if ((request.getParameter("strCareOf").trim() != null && request.getParameter("strCareOf").trim().length() != 0) || (request.getParameter("strBuilding").trim() != null && request.getParameter("strBuilding").trim().length() != 0) || (request.getParameter("strLandmark") != null && request.getParameter("strLandmark").trim().length() != 0) || (request.getParameter("strStreet").trim() != null && request.getParameter("strStreet").trim().length() != 0) || (request.getParameter("strLocality").trim() != null && request.getParameter("strLocality").trim().length() != 0) || (request.getParameter("strPoName").trim() != null && request.getParameter("strPoName").trim().length() != 0) || (request.getParameter("strVillage").trim() != null && request.getParameter("strVillage").trim().length() != 0) || (request.getParameter("strSubdist").trim() != null && request.getParameter("strSubdist").trim().length() != 0) || (request.getParameter("strDistrict").trim() != null && request.getParameter("strDistrict").trim().length() != 0) || (request.getParameter("strState").trim() != null && request.getParameter("strState").trim().length() != 0) || (request.getParameter("strPincode").trim() != null && request.getParameter("strPincode").trim().length() != 0)) {

				piValue = false;
				paValue = true;
				pfaValue = false;

				dd.getPersonalAddress().setUsePa(paValue);

				if ((request.getParameter("strCareOf").trim() != null && request.getParameter("strCareOf").trim().length() != 0)) {
					dd.getPersonalAddress().setCareOf(request.getParameter("strCareOf").trim());

				} else if ((request.getParameter("strBuilding").trim() != null && request.getParameter("strBuilding").trim().length() != 0)) {
					dd.getPersonalAddress().setHouse(request.getParameter("strBuilding").trim());

				} else if ((request.getParameter("strLandmark").trim() != null && request.getParameter("strLandmark").trim().length() != 0)) {
					dd.getPersonalAddress().setLandmark(request.getParameter("strLandmark").trim());

				} else if ((request.getParameter("strStreet").trim() != null && request.getParameter("strStreet").trim().length() != 0)) {
					dd.getPersonalAddress().setStreet(request.getParameter("strStreet").trim());

				} else if ((request.getParameter("strLocality").trim() != null && request.getParameter("strLocality").trim().length() != 0)) {
					dd.getPersonalAddress().setLocality(request.getParameter("strLocality").trim());

				} else if ((request.getParameter("strPoName").trim() != null && request.getParameter("strPoName").trim().length() != 0)) {
					dd.getPersonalAddress().setPostOffice(request.getParameter("strPoName").trim());

				} else if ((request.getParameter("strVillage").trim() != null && request.getParameter("strVillage").trim().length() != 0)) {

					dd.getPersonalAddress().setVillageTownCity(request.getParameter("strVillage").trim());

				} else if ((request.getParameter("strSubdist").trim() != null && request.getParameter("strSubdist").trim().length() != 0)) {
					dd.getPersonalAddress().setSubDistrict(request.getParameter("strSubdist").trim());

				} else if ((request.getParameter("strDistrict").trim() != null && request.getParameter("strDistrict").trim().length() != 0)) {
					dd.getPersonalAddress().setDistrict(request.getParameter("strDistrict").trim());

				} else if ((request.getParameter("strState").trim() != null && request.getParameter("strState").trim().length() != 0)) {
					dd.getPersonalAddress().setState(request.getParameter("strState").trim());

				} else if ((request.getParameter("strPincode").trim() != null && request.getParameter("strPincode").trim().length() != 0)) {
					dd.getPersonalAddress().setPincode(request.getParameter("strPincode").trim());

				}

			}

			/*
			 * Prepare PID Block - The following code is recemonded to be
			 * executed in the system capturing Biometric data
			 */
			pro.prepareDemographicPidBlock(dd, "AUT122333");

			/**
			 * Prepare AuthXML For Demo Auth For Sending Request To Asa
			 * 
			 */
			String requestXml = "";
			String responseXml = "";
			try {
				requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

			} catch (Exception ex) {

				ex.getStackTrace();
			}

			try {

				DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate = new Date();
				request_time = dateFormat.format(reqdate);

				// responseXml = HttpConnector.excutePostHttpXml(PREAUAProperties.getAsa_request_url(), requestXml);
				responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);

				/*
				 * Response XML FROM CSC
				 **/

				if (responseXml.startsWith("<Error>")) {

					Log.aua.info("Response DATA:Aadhaar Number::" + aadharcardnumber + "Error Message::" + pro.getXml());

				}

				/*
				 * Validate XML and Deserialize Ksa response XML
				 */

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				AuthRes res = pro.parse(responseXml);
				if (res.getRet() == AuthResult.Y) {

					JSONObject jo = new JSONObject();
					jo.put("aadhaarnumber", aadharcardnumber);
					jo.put("name", request.getParameter("name"));
					jo.put("gender", request.getParameter("gender"));
					jo.put("dob", dob);
					jo.put("mobileno", request.getParameter("mobileno"));
					jo.put("email", request.getParameter("email"));
					jo.put("strAddressValue", request.getParameter("strAddressValue"));
					jo.put("strCareOf", request.getParameter("strCareOf"));
					jo.put("strBuilding", request.getParameter("strBuilding"));
					jo.put("strLandmark", request.getParameter("strLandmark"));
					jo.put("strStreet", request.getParameter("strStreet"));
					jo.put("strLocality", request.getParameter("strLocality"));
					jo.put("strPoName", request.getParameter("strPoName"));
					jo.put("strVillage", request.getParameter("strVillage"));
					jo.put("strSubdist", request.getParameter("strSubdist"));
					jo.put("strDistrict", request.getParameter("strDistrict"));
					jo.put("strState", request.getParameter("strState"));
					jo.put("strPincode", request.getParameter("strPincode"));
					jo.put("message", "<span style=\"color:#83B358;font-weight:bold\">Authentication Success</span>");
					int aastatus = 1;

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + res.getTxn());

					// **SAVING DATA***//

					/// ***VERIFICATION DETAILS***//

					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("DEMOAUTH");
					veri.setMESSAGE("Authentication Success");
					veri.setUID(Long.parseLong(aadharcardnumber));
					veri.setTRANSACTION_ID(res.getTxn());
					veri.setSERVER_RESPONSE_ON(res.getTs());
					veri.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(1);
					veri.setREFERENCE_NUMBER(res.getCode());
					veri.setSTATUS_DESCRIPTION("Authentication Success");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setAPI_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);

					// *****VERIFICATION DETAILS********//

					// ****PERSONAL DATA****//
					Personal pers = null;
					pers = new Personal();

					if (uidname != null && !uidname.isEmpty()) {
						pers.setNAME(uidname);
					}
					if (dob != null && !dob.isEmpty()) {
						if (dob.length() <= 4)
							pers.setDOB(dob + "-00" + "-00");
						else
							pers.setDOB(dob);

					}
					if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
						pers.setGENDER(request.getParameter("gender"));
					}
					if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
						pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
					}
					if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
						pers.setEMAIL(request.getParameter("email"));
					}
					pers.setAB_VERIFICATION_ID(veri.getID());

					if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
						int personID = personalDAO.save(pers);
					}

					// ***END RESIDENTIAL DETAILS***//

					// **ENDING SAVING DATA**//

					// *******END PERSONAL DATA*******//
					// *****RESIDENTAL DETIALS*****//
					Residential resp = null;
					resp = new Residential();
					if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
						resp.setCARE_OF(request.getParameter("strCareOf").trim());
					}

					if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
						resp.setBUILDING(request.getParameter("strBuilding").trim());
					}

					if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
						resp.setSTREET(request.getParameter("strLandmark").trim());
					}

					if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
						resp.setLANDMARK(request.getParameter("strStreet").trim());
					}
					if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
						resp.setLOCALITY(request.getParameter("strLocality").trim());
					}
					if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
						resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
					}
					if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
						resp.setDISTRICT(request.getParameter("strDistrict").trim());
					}
					if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
						resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
					}
					if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
						resp.setPONAME(request.getParameter("strPoName").trim());
					}
					if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
						resp.setSTATE(request.getParameter("strState").trim());
					}

					if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
						resp.setPINCODE(request.getParameter("strPincode").trim());
					}

					if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
						resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
					}

					if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
						resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
					}

					resp.setAB_VERIFICATION_ID(veri.getID());
					if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
						int resId = residentialDAO.save(resp);
					}

					// ***END RESIDENTIAL DETAILS***//

					// **ENDING SAVING DATA**//

					return jo.toString();
				} else {

					JSONObject jo = new JSONObject();
					jo.put("aadhaarnumber", aadharcardnumber);
					jo.put("name", request.getParameter("name"));
					jo.put("gender", request.getParameter("gender"));
					jo.put("dob", dob);
					jo.put("mobileno", request.getParameter("mobileno"));
					jo.put("email", request.getParameter("email"));
					jo.put("strAddressValue", request.getParameter("strAddressValue"));
					jo.put("strCareOf", request.getParameter("strCareOf"));
					jo.put("strBuilding", request.getParameter("strBuilding"));
					jo.put("strLandmark", request.getParameter("strLandmark"));
					jo.put("strStreet", request.getParameter("strStreet"));
					jo.put("strLocality", request.getParameter("strLocality"));
					jo.put("strPoName", request.getParameter("strPoName"));
					jo.put("strVillage", request.getParameter("strVillage"));
					jo.put("strSubdist", request.getParameter("strSubdist"));
					jo.put("strDistrict", request.getParameter("strDistrict"));
					jo.put("strState", request.getParameter("strState"));
					jo.put("strPincode", request.getParameter("strPincode"));

					int aastatus = 1;
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + res.getErr() + "::ResTranscation id:" + res.getTxn());

					// **SAVING DATA***//

					/// ***VERIFICATION DETAILS***//

					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("DEMOAUTH");
					veri.setMESSAGE("Authentication Failure");
					veri.setERROR_CODE(res.getErr());
					veri.setUID(Long.parseLong(aadharcardnumber));
					veri.setTRANSACTION_ID(res.getTxn());
					veri.setSERVER_RESPONSE_ON(res.getTs());
					veri.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setREFERENCE_NUMBER(res.getCode());
					veri.setSTATUS_DESCRIPTION("Authentication Failure");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setAPI_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);

					// *****VERIFICATION DETAILS********//

					// ****PERSONAL DATA****//
					Personal pers = null;
					pers = new Personal();

					if (uidname != null && !uidname.isEmpty()) {
						pers.setNAME(uidname);
					}
					if (dob != null && !dob.isEmpty()) {
						if (dob.length() <= 4)
							pers.setDOB(dob + "-00" + "-00");
						else
							pers.setDOB(dob);
					}
					if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
						pers.setGENDER(request.getParameter("gender"));
					}

					if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
						pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
					}
					if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
						pers.setEMAIL(request.getParameter("email"));
					}
					pers.setAB_VERIFICATION_ID(veri.getID());

					if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
						int personID = personalDAO.save(pers);
					}

					// ***END RESIDENTIAL DETAILS***//

					// **ENDING SAVING DATA**//

					// *******END PERSONAL DATA*******//
					// *****RESIDENTAL DETIALS*****//
					Residential resp = null;
					resp = new Residential();
					if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
						resp.setCARE_OF(request.getParameter("strCareOf").trim());
					}

					if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
						resp.setBUILDING(request.getParameter("strBuilding").trim());
					}

					if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
						resp.setSTREET(request.getParameter("strLandmark").trim());
					}

					if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
						resp.setLANDMARK(request.getParameter("strStreet").trim());
					}
					if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
						resp.setLOCALITY(request.getParameter("strLocality").trim());
					}
					if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
						resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
					}
					if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
						resp.setDISTRICT(request.getParameter("strDistrict").trim());
					}
					if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
						resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
					}
					if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
						resp.setPONAME(request.getParameter("strPoName").trim());
					}
					if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
						resp.setSTATE(request.getParameter("strState").trim());
					}

					if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
						resp.setPINCODE(request.getParameter("strPincode").trim());
					}

					if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
						resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
					}

					if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
						resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
					}

					resp.setAB_VERIFICATION_ID(veri.getID());
					if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").trim().isEmpty()) {
						int resId = residentialDAO.save(resp);
					}

					// ***END RESIDENTIAL DETAILS***//

					// **ENDING SAVING DATA**//

					HashMap<String, String> map = new HashMap<String, String>();
					map.put("100", "Pi (basic) attributes of demographic data did not match");
					map.put("200", "Pa (address) attributes of demographic data did not match");
					map.put("300", "Biometric data did not match");
					map.put("312", "FMR and FIR cannot be used in same transaction");
					map.put("313", "Single FIR record contains more than one finger");
					map.put("314", "Number of FMR/FIR should not exceed 10");
					map.put("315", "Number of IIR should not exceed 2");
					map.put("500", "Invalid encryption of Skey");
					map.put("501", "Invalid certificate identifier in ci attribute of Skey");
					map.put("502", "Invalid encryption of Pid");
					map.put("503", "Invalid encryption of Hmac");
					map.put("504", "Session key re-initiation required due to expiry or key out of sync");
					map.put("510", "Invalid Auth XML format");
					map.put("511", "Invalid PID XML format");
					map.put("520", "Invalid device");
					map.put("530", "Invalid authenticator code");
					map.put("540", "Invalid Auth XML version");
					map.put("541", "Invalid PID XML version");
					map.put("542", "AUA not authorized for ASA. This error will be returned if AUA and ASA do not have linking in the portal");
					map.put("543", "Sub-AUA not associated with AUA. This error will be returned if Sub-AUA specified in sa attribute is not added as Sub-AUA in portal");
					map.put("550", "Invalid Uses element attributes");
					map.put("561", "Request expired");
					map.put("562", "Timestamp value is future time");
					map.put("563", "Duplicate request");
					map.put("564", "HMAC Validation failed");
					map.put("565", "AUA license key has expired or is invalid");
					map.put("566", "ASA license key has expired or is invalid");
					map.put("567", "Invalid input");
					map.put("568", "Unsupported Language");
					map.put("569", "Digital signature verification failed");
					map.put("570", "Invalid key info in digital signature");
					map.put("571", "PIN Requires reset");
					map.put("572", "Invalid biometric position");
					map.put("573", "Pi usage not allowed as per license");
					map.put("574", "Pa usage not allowed as per license");
					map.put("575", "Pfa usage not allowed as per license");
					map.put("576", "FMR usage not allowed as per license");
					map.put("577", "FIR usage not allowed as per license");
					map.put("578", "IIR usage not allowed as per license");
					map.put("579", "OTP usage not allowed as per license");
					map.put("580", "PIN usage not allowed as per license");
					map.put("581", "Fuzzy matching usage not allowed as per license");
					map.put("582", "Local language usage not allowed as per license");
					map.put("710", "Missing Pi data as specified in Uses");
					map.put("720", "Missing Pa data as specified in Uses");
					map.put("721", "Missing Pfa data as specified in Uses");
					map.put("730", "Missing PIN data as specified in Uses");
					map.put("740", "Missing OTP data as specified in Uses");
					map.put("800", "Invalid biometric data");
					map.put("810", "Missing biometric data as specified in Uses");
					map.put("811", "Missing biometric data in CIDR for the given Aadhaar number");
					map.put("812", "Resident has not done Best Finger Detection. Application should initiate BFD application to help resident identify their best fingers. See Aadhaar Best Finger Detection API specification");
					map.put("820", "Missing or empty value for bt attribute in Uses element");
					map.put("821", "Invalid value in the bt attribute of Uses element");
					map.put("901", "No authentication data found in the request");
					map.put("902", "Invalid dob value in the Pi element");
					map.put("910", "Invalid mv value in the Pi element");
					map.put("911", "Invalid mv value in the Pfa element");
					map.put("912", "Invalid ms value");
					map.put("913", "Both Pa and Pfa are present in the authentication request");
					map.put("931", "Technical error that are internal to authentication server");
					map.put("932", "Technical error that are internal to authentication server");
					map.put("933", "Technical error that are internal to authentication server");
					map.put("934", "Technical error that are internal to authentication server");
					map.put("935", "Technical error that are internal to authentication server");
					map.put("936", "Technical error that are internal to authentication server");
					map.put("937", "Technical error that are internal to authentication server");
					map.put("938", "Technical error that are internal to authentication server");
					map.put("939", "Technical error that are internal to authentication server");
					map.put("996", "Aadhaar is Canceled Resident should Contact UIDAI Contact Center");
					map.put("940", "Unauthorized ASA channel");
					map.put("941", "Unspecified ASA channel");
					map.put("980", "Unsupported option");
					map.put("998", "Aadhaar number is not valid");
					map.put("996", "Aadhaar is cancelled resident shall contact UIDAI contact center");
					map.put("997", "Aadhaar is suspended resident shall visit permanent enrolment center");
					map.put("999", "Unknown error");
					String uidmessage = null;

					for (String actualKey : map.keySet()) {
						// String value = map.get(actualKey);

						if (actualKey.contains(res.getErr().trim())) {
							uidmessage = map.get(actualKey);
							jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure Error Code-" + res.getErr() + "</span>" + "<br/><br/>" + "<span style=\"color: #f31818;font-weight: bold;font-size: 9px;\">" + uidmessage + "</span>");

						}

					}

					return jo.toString();

				}

			} catch (XMLParsingException ex) {

				ex.getException().printStackTrace();

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				JSONObject jo = new JSONObject();
				jo.put("aadhaarnumber", aadharcardnumber);
				jo.put("name", request.getParameter("name"));
				jo.put("gender", request.getParameter("gender"));
				jo.put("dob", dob);
				jo.put("mobileno", request.getParameter("mobileno"));
				jo.put("email", request.getParameter("email"));
				jo.put("strAddressValue", request.getParameter("strAddressValue"));
				jo.put("strCareOf", request.getParameter("strCareOf"));
				jo.put("strBuilding", request.getParameter("strBuilding"));
				jo.put("strLandmark", request.getParameter("strLandmark"));
				jo.put("strStreet", request.getParameter("strStreet"));
				jo.put("strLocality", request.getParameter("strLocality"));
				jo.put("strPoName", request.getParameter("strPoName"));
				jo.put("strVillage", request.getParameter("strVillage"));
				jo.put("strSubdist", request.getParameter("strSubdist"));
				jo.put("strDistrict", request.getParameter("strDistrict"));
				jo.put("strState", request.getParameter("strState"));
				jo.put("strPincode", request.getParameter("strPincode"));
				jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure " + ex.getMessage() + "</span>");

				// **SAVING DATA***//
				/// ***VERIFICATION DETAILS***//

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("DEMOAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(((Element) doc).select("Code").text());
				veri.setUID(Long.parseLong(aadharcardnumber));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				// veri.setREFERENCE_NUMBER("123");
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				// *****VERIFICATION DETAILS********//

				// ****PERSONAL DATA****//
				Personal pers = null;
				pers = new Personal();

				if (uidname != null && !uidname.isEmpty()) {
					pers.setNAME(uidname);
				}
				if (dob != null && !dob.isEmpty()) {
					if (dob.length() <= 4)
						pers.setDOB(dob + "-00" + "-00");
					else
						pers.setDOB(dob);
				}
				if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
					pers.setGENDER(request.getParameter("gender"));
				}
				if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
					pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
				}
				if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
					pers.setEMAIL(request.getParameter("email"));
				}
				pers.setAB_VERIFICATION_ID(veri.getID());

				if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
					int personID = personalDAO.save(pers);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				// *******END PERSONAL DATA*******//
				// *****RESIDENTAL DETIALS*****//
				Residential resp = null;
				resp = new Residential();
				if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
					resp.setCARE_OF(request.getParameter("strCareOf").trim());
				}

				if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
					resp.setBUILDING(request.getParameter("strBuilding").trim());
				}

				if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
					resp.setSTREET(request.getParameter("strLandmark").trim());
				}

				if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
					resp.setLANDMARK(request.getParameter("strStreet").trim());
				}
				if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
					resp.setLOCALITY(request.getParameter("strLocality").trim());
				}
				if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
					resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
				}
				if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
					resp.setDISTRICT(request.getParameter("strDistrict").trim());
				}
				if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
					resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
				}
				if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
					resp.setPONAME(request.getParameter("strPoName").trim());
				}
				if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
					resp.setSTATE(request.getParameter("strState").trim());
				}

				if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
					resp.setPINCODE(request.getParameter("strPincode").trim());
				}

				if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
					resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
				}

				if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
					resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
				}

				resp.setAB_VERIFICATION_ID(veri.getID());
				if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
					int resId = residentialDAO.save(resp);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
				return jo.toString();

			} catch (AsaServerException ex) {

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				JSONObject jo = new JSONObject();
				jo.put("aadhaarnumber", aadharcardnumber);
				jo.put("name", request.getParameter("name"));
				jo.put("gender", request.getParameter("gender"));
				jo.put("dob", dob);
				jo.put("mobileno", request.getParameter("mobileno"));
				jo.put("email", request.getParameter("email"));
				jo.put("strAddressValue", request.getParameter("strAddressValue"));
				jo.put("strCareOf", request.getParameter("strCareOf"));
				jo.put("strBuilding", request.getParameter("strBuilding"));
				jo.put("strLandmark", request.getParameter("strLandmark"));
				jo.put("strStreet", request.getParameter("strStreet"));
				jo.put("strLocality", request.getParameter("strLocality"));
				jo.put("strPoName", request.getParameter("strPoName"));
				jo.put("strVillage", request.getParameter("strVillage"));
				jo.put("strSubdist", request.getParameter("strSubdist"));
				jo.put("strDistrict", request.getParameter("strDistrict"));
				jo.put("strState", request.getParameter("strState"));
				jo.put("strPincode", request.getParameter("strPincode"));
				jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure " + ex.getMessage() + "</span>");

				// **SAVING DATA***//

				/// ***VERIFICATION DETAILS***//

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("DEMOAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(((Element) doc).select("Code").text());
				veri.setUID(Long.parseLong(aadharcardnumber));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				// veri.setREFERENCE_NUMBER("123");
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				// *****VERIFICATION DETAILS********//

				// ****PERSONAL DATA****//
				Personal pers = null;
				pers = new Personal();

				if (uidname != null && !uidname.isEmpty()) {
					pers.setNAME(uidname);
				}
				if (dob != null && !dob.isEmpty()) {
					if (dob.length() <= 4)
						pers.setDOB(dob + "-00" + "-00");
					else
						pers.setDOB(dob);
				}
				if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
					pers.setGENDER(request.getParameter("gender"));
				}
				if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
					pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
				}
				if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
					pers.setEMAIL(request.getParameter("email"));
				}
				pers.setAB_VERIFICATION_ID(veri.getID());

				if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
					int personID = personalDAO.save(pers);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				// *******END PERSONAL DATA*******//
				// *****RESIDENTAL DETIALS*****//
				Residential resp = null;
				resp = new Residential();
				if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
					resp.setCARE_OF(request.getParameter("strCareOf").trim());
				}

				if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
					resp.setBUILDING(request.getParameter("strBuilding").trim());
				}

				if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
					resp.setSTREET(request.getParameter("strLandmark").trim());
				}

				if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
					resp.setLANDMARK(request.getParameter("strStreet").trim());
				}
				if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
					resp.setLOCALITY(request.getParameter("strLocality").trim());
				}
				if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
					resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
				}
				if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
					resp.setDISTRICT(request.getParameter("strDistrict").trim());
				}
				if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
					resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
				}
				if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
					resp.setPONAME(request.getParameter("strPoName").trim());
				}
				if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
					resp.setSTATE(request.getParameter("strState").trim());
				}

				if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
					resp.setPINCODE(request.getParameter("strPincode").trim());
				}

				if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
					resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
				}

				if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
					resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
				}

				resp.setAB_VERIFICATION_ID(veri.getID());
				if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
					int resId = residentialDAO.save(resp);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
				return jo.toString();

			} catch (InvalidResponseException ex) {

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				JSONObject jo = new JSONObject();
				jo.put("aadhaarnumber", aadharcardnumber);
				jo.put("name", request.getParameter("name"));
				jo.put("gender", request.getParameter("gender"));
				jo.put("dob", dob);
				jo.put("mobileno", request.getParameter("mobileno"));
				jo.put("email", request.getParameter("email"));
				jo.put("strAddressValue", request.getParameter("strAddressValue"));
				jo.put("strCareOf", request.getParameter("strCareOf"));
				jo.put("strBuilding", request.getParameter("strBuilding"));
				jo.put("strLandmark", request.getParameter("strLandmark"));
				jo.put("strStreet", request.getParameter("strStreet"));
				jo.put("strLocality", request.getParameter("strLocality"));
				jo.put("strPoName", request.getParameter("strPoName"));
				jo.put("strVillage", request.getParameter("strVillage"));
				jo.put("strSubdist", request.getParameter("strSubdist"));
				jo.put("strDistrict", request.getParameter("strDistrict"));
				jo.put("strState", request.getParameter("strState"));
				jo.put("strPincode", request.getParameter("strPincode"));
				jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure " + ex.getMessage() + "</span>");

				// **SAVING DATA***//

				/// ***VERIFICATION DETAILS***//

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("DEMOAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(((Element) doc).select("Code").text());
				veri.setUID(Long.parseLong(aadharcardnumber));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				// veri.setREFERENCE_NUMBER("123");
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				// *****VERIFICATION DETAILS********//

				// ****PERSONAL DATA****//
				Personal pers = null;
				pers = new Personal();

				if (uidname != null && !uidname.isEmpty()) {
					pers.setNAME(uidname);
				}
				if (dob != null && !dob.isEmpty()) {
					if (dob.length() <= 4)
						pers.setDOB(dob + "-00" + "-00");
					else
						pers.setDOB(dob);

				}
				if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
					pers.setGENDER(request.getParameter("gender"));
				}
				if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
					pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
				}
				if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
					pers.setEMAIL(request.getParameter("email"));
				}
				pers.setAB_VERIFICATION_ID(veri.getID());

				if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
					int personID = personalDAO.save(pers);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				// *******END PERSONAL DATA*******//
				// *****RESIDENTAL DETIALS*****//
				Residential resp = null;
				resp = new Residential();
				if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
					resp.setCARE_OF(request.getParameter("strCareOf").trim());
				}

				if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
					resp.setBUILDING(request.getParameter("strBuilding").trim());
				}

				if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
					resp.setSTREET(request.getParameter("strLandmark").trim());
				}

				if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
					resp.setLANDMARK(request.getParameter("strStreet").trim());
				}
				if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
					resp.setLOCALITY(request.getParameter("strLocality").trim());
				}
				if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
					resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
				}
				if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
					resp.setDISTRICT(request.getParameter("strDistrict").trim());
				}
				if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
					resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
				}
				if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
					resp.setPONAME(request.getParameter("strPoName").trim());
				}
				if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
					resp.setSTATE(request.getParameter("strState").trim());
				}

				if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
					resp.setPINCODE(request.getParameter("strPincode").trim());
				}

				if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
					resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
				}

				if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
					resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
				}

				resp.setAB_VERIFICATION_ID(veri.getID());
				if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
					int resId = residentialDAO.save(resp);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
				return jo.toString();

			} catch (UidaiSignatureVerificationFailedException ex) {

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				JSONObject jo = new JSONObject();
				jo.put("aadhaarnumber", aadharcardnumber);
				jo.put("name", request.getParameter("name"));
				jo.put("gender", request.getParameter("gender"));
				jo.put("dob", dob);
				jo.put("mobileno", request.getParameter("mobileno"));
				jo.put("email", request.getParameter("email"));
				jo.put("strAddressValue", request.getParameter("strAddressValue"));
				jo.put("strCareOf", request.getParameter("strCareOf"));
				jo.put("strBuilding", request.getParameter("strBuilding"));
				jo.put("strLandmark", request.getParameter("strLandmark"));
				jo.put("strStreet", request.getParameter("strStreet"));
				jo.put("strLocality", request.getParameter("strLocality"));
				jo.put("strPoName", request.getParameter("strPoName"));
				jo.put("strVillage", request.getParameter("strVillage"));
				jo.put("strSubdist", request.getParameter("strSubdist"));
				jo.put("strDistrict", request.getParameter("strDistrict"));
				jo.put("strState", request.getParameter("strState"));
				jo.put("strPincode", request.getParameter("strPincode"));
				jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure " + ex.getMessage() + "</span>");
				// **SAVING DATA***//

				/// ***VERIFICATION DETAILS***//

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("DEMOAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(((Element) doc).select("Code").text());
				veri.setUID(Long.parseLong(aadharcardnumber));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				// veri.setREFERENCE_NUMBER("123");
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				// *****VERIFICATION DETAILS********//

				// ****PERSONAL DATA****//
				Personal pers = null;
				pers = new Personal();

				if (uidname != null && !uidname.isEmpty()) {
					pers.setNAME(uidname);
				}
				if (dob != null && !dob.isEmpty()) {
					if (dob.length() <= 4)
						pers.setDOB(dob + "-00" + "-00");
					else
						pers.setDOB(dob);
				}
				if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
					pers.setGENDER(request.getParameter("gender"));
				}
				if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
					pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
				}
				if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
					pers.setEMAIL(request.getParameter("email"));
				}
				pers.setAB_VERIFICATION_ID(veri.getID());

				if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
					int personID = personalDAO.save(pers);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				// *******END PERSONAL DATA*******//
				// *****RESIDENTAL DETIALS*****//
				Residential resp = null;
				resp = new Residential();
				if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
					resp.setCARE_OF(request.getParameter("strCareOf").trim());
				}

				if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
					resp.setBUILDING(request.getParameter("strBuilding").trim());
				}

				if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
					resp.setSTREET(request.getParameter("strLandmark").trim());
				}

				if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
					resp.setLANDMARK(request.getParameter("strStreet").trim());
				}
				if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
					resp.setLOCALITY(request.getParameter("strLocality").trim());
				}
				if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
					resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
				}
				if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
					resp.setDISTRICT(request.getParameter("strDistrict").trim());
				}
				if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
					resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
				}
				if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
					resp.setPONAME(request.getParameter("strPoName").trim());
				}
				if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
					resp.setSTATE(request.getParameter("strState").trim());
				}

				if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
					resp.setPINCODE(request.getParameter("strPincode").trim());
				}

				if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
					resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
				}

				if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
					resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
				}

				resp.setAB_VERIFICATION_ID(veri.getID());
				if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
					int resId = residentialDAO.save(resp);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
				return jo.toString();

			}

			catch (Exception e) {

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);

				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				JSONObject jo = new JSONObject();
				jo.put("aadhaarnumber", aadharcardnumber);
				jo.put("name", request.getParameter("name"));
				jo.put("gender", request.getParameter("gender"));
				jo.put("dob", dob);
				jo.put("mobileno", request.getParameter("mobileno"));
				jo.put("email", request.getParameter("email"));
				jo.put("strAddressValue", request.getParameter("strAddressValue"));
				jo.put("strCareOf", request.getParameter("strCareOf"));
				jo.put("strBuilding", request.getParameter("strBuilding"));
				jo.put("strLandmark", request.getParameter("strLandmark"));
				jo.put("strStreet", request.getParameter("strStreet"));
				jo.put("strLocality", request.getParameter("strLocality"));
				jo.put("strPoName", request.getParameter("strPoName"));
				jo.put("strVillage", request.getParameter("strVillage"));
				jo.put("strSubdist", request.getParameter("strSubdist"));
				jo.put("strDistrict", request.getParameter("strDistrict"));
				jo.put("strState", request.getParameter("strState"));
				jo.put("strPincode", request.getParameter("strPincode"));
				jo.put("message", "<span style=\"color:#C35D34;font-weight:bold\">Authentication Failure " + e.getMessage() + "</span>");

				// **SAVING DATA***//

				/// ***VERIFICATION DETAILS***//

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("DEMOAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(((Element) doc).select("Code").text());
				veri.setUID(Long.parseLong(aadharcardnumber));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				// veri.setREFERENCE_NUMBER("123");
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				// *****VERIFICATION DETAILS********//

				// ****PERSONAL DATA****//
				Personal pers = null;
				pers = new Personal();

				if (uidname != null && !uidname.isEmpty()) {
					pers.setNAME(uidname);
				}
				if (dob != null && !dob.isEmpty()) {
					if (dob.length() <= 4)
						pers.setDOB(dob + "-00" + "-00");
					else
						pers.setDOB(dob);
				}
				if (request.getParameter("gender") != null && !request.getParameter("gender").isEmpty()) {
					pers.setGENDER(request.getParameter("gender"));
				}
				if (request.getParameter("mobileno") != null && !request.getParameter("mobileno").isEmpty()) {
					pers.setMOBILE_NUMBER(request.getParameter("mobileno"));
				}
				if (request.getParameter("email") != null && !request.getParameter("email").isEmpty()) {
					pers.setEMAIL(request.getParameter("email"));
				}
				pers.setAB_VERIFICATION_ID(veri.getID());

				if (!uidname.isEmpty() || !dob.isEmpty() || !request.getParameter("gender").isEmpty() || !request.getParameter("mobileno").isEmpty() || !request.getParameter("email").isEmpty()) {
					int personID = personalDAO.save(pers);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				// *******END PERSONAL DATA*******//
				// *****RESIDENTAL DETIALS*****//
				Residential resp = null;
				resp = new Residential();
				if (request.getParameter("strCareOf") != null && !request.getParameter("strCareOf").isEmpty()) {
					resp.setCARE_OF(request.getParameter("strCareOf").trim());
				}

				if (request.getParameter("strBuilding") != null && !request.getParameter("strBuilding").isEmpty()) {
					resp.setBUILDING(request.getParameter("strBuilding").trim());
				}

				if (request.getParameter("strLandmark") != null && !request.getParameter("strLandmark").isEmpty()) {
					resp.setSTREET(request.getParameter("strLandmark").trim());
				}

				if (request.getParameter("strStreet") != null && !request.getParameter("strStreet").isEmpty()) {
					resp.setLANDMARK(request.getParameter("strStreet").trim());
				}
				if (request.getParameter("strLocality") != null && !request.getParameter("strLocality").isEmpty()) {
					resp.setLOCALITY(request.getParameter("strLocality").trim());
				}
				if (request.getParameter("strVillage") != null && !request.getParameter("strVillage").isEmpty()) {
					resp.setVILLAGE_TOWN_CITY(request.getParameter("strVillage").trim());
				}
				if (request.getParameter("strDistrict") != null && !request.getParameter("strDistrict").isEmpty()) {
					resp.setDISTRICT(request.getParameter("strDistrict").trim());
				}
				if (request.getParameter("strSubdist") != null && !request.getParameter("strSubdist").isEmpty()) {
					resp.setSUBDISTRICT(request.getParameter("strSubdist").trim());
				}
				if (request.getParameter("strPoName") != null && !request.getParameter("strPoName").isEmpty()) {
					resp.setPONAME(request.getParameter("strPoName").trim());
				}
				if (request.getParameter("strState") != null && !request.getParameter("strState").isEmpty()) {
					resp.setSTATE(request.getParameter("strState").trim());
				}

				if (request.getParameter("strPincode") != null && !request.getParameter("strPincode").isEmpty()) {
					resp.setPINCODE(request.getParameter("strPincode").trim());
				}

				if (request.getParameter("COUNTRY") != null && !request.getParameter("COUNTRY").isEmpty()) {
					resp.setCOUNTRY(request.getParameter("COUNTRY").trim());
				}

				if (request.getParameter("strAddressValue") != null && !request.getParameter("strAddressValue").isEmpty()) {
					resp.setFULLADDRESS(request.getParameter("strAddressValue").trim());
				}

				resp.setAB_VERIFICATION_ID(veri.getID());
				if (!request.getParameter("strCareOf").isEmpty() || !request.getParameter("strBuilding").isEmpty() || !request.getParameter("strLandmark").isEmpty() || !request.getParameter("strStreet").isEmpty() || !request.getParameter("strLocality").isEmpty() || !request.getParameter("strVillage").isEmpty() || !request.getParameter("strDistrict").isEmpty() || !request.getParameter("strSubdist").isEmpty() || !request.getParameter("strPoName").isEmpty() || !request.getParameter("strState").isEmpty() || !request.getParameter("strPincode").isEmpty() || !request.getParameter("strAddressValue").isEmpty()) {
					int resId = residentialDAO.save(resp);
				}

				// ***END RESIDENTIAL DETAILS***//

				// **ENDING SAVING DATA**//

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
				return jo.toString();
			}

		}

		else {
			Log.aua.info("Response DATA:" + "Authentication Failure" + "::" + "Login By::" + session.getAttribute("user_login_name"));
			return ("redirect:/login.html");

		}

	}

}
