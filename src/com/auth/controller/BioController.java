package com.auth.controller;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import com.auth.bean.Verification;
import com.auth.dao.BioDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.domain.BioUser;
import com.auth.util.AUAUtilities;
import com.auth.util.IpassCustomBase64;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
import com.ecs.asa.processor.AuthProcessor;
import com.ecs.asa.processor.AuthProcessor.RcType;
import com.ecs.asa.processor.AuthProcessor.TidType;
import com.ecs.asa.processor.BfdProcessor;
//import com.ecs.asa.processor.BfdProcessor.TidType;
import com.ecs.asa.utils.HttpConnector;
import com.ecs.aua.rbdgen.support.BfdData;
import com.ecs.aua.rbdgen.support.FingerPosition;
import com.ecs.exceptions.AsaServerException;
import com.ecs.exceptions.InvalidResponseException;
import com.ecs.exceptions.UidaiSignatureVerificationFailedException;
import com.ecs.exceptions.XMLParsingException;
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;
import in.gov.uidai.authentication.uid_bfd_response._1.BfdRes;

/**
 * The Class BioController.
 */
@SessionAttributes("sessionanumber")
@Controller
public class BioController {

	/** set Global Varibales */
	private String udc = null;

	/** The user login DAO. */
	@Autowired
	private UserLoginDAO userLogindao;

	@Autowired
	private BioDAO bioDAO;

	@Autowired
	private VerificationDAO verificationDAO;

	/**
	 * BIO Auth Home Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/bio", method = RequestMethod.GET)
	public ModelAndView Bio(Model model, HttpSession session) throws Exception {

		String propFilePath = "";
		try {
			PREAUAProperties.load();
			int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));
			if (session.getAttribute("user_login_name") != null && access == 1) {
				Log.aua.info("User Login ::" + session.getAttribute("user_login_name") + "Status::Successfull");
				return new ModelAndView("BioAuth");
			} else {

				return new ModelAndView("redirect:/login.html");

			}
		} catch (Exception e) {
			System.out.println(e);
			return new ModelAndView("redirect:/login.html");
		}

	}

	/**
	 * Biomatric Image Captured Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/startek220", method = RequestMethod.GET)
	public ModelAndView StartekFm220(Model model, HttpSession session) throws Exception {

		String propFilePath = "";
		try {
			PREAUAProperties.load();
			int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));

			if (session.getAttribute("user_login_name") != null && access == 1) {

				return new ModelAndView("startek220");
			} else {
				return new ModelAndView("redirect:/login.html");

			}
		} catch (Exception e) {
			System.out.println(e);
			return new ModelAndView("redirect:/login.html");
		}

	}

	/**
	 * Biomatric Image Captured Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/startekBFD220", method = RequestMethod.GET)
	public ModelAndView Startekbfd220(Model model, HttpSession session) throws Exception {

		String propFilePath = "";
		try {
			PREAUAProperties.load();
			int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));

			if (session.getAttribute("user_login_name") != null && access == 1) {
				Log.aua.info("User Login ::" + session.getAttribute("user_login_name") + "Status::Successfull");
				return new ModelAndView("startekBFD220");
			} else {
				return new ModelAndView("redirect:/login.html");

			}
		} catch (Exception e) {
			System.out.println(e);
			return new ModelAndView("redirect:/login.html");
		}

	}

	/**
	 * Fingerprint BioAuh Request.
	 *
	 * @param biouser
	 *            the biouser
	 * @param model
	 *            the model
	 * @param request
	 *            the request
	 * @param session
	 *            the session
	 * @return the string
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/processBioAuth", method = { RequestMethod.POST })
	public @ResponseBody String processBioAuth(@ModelAttribute("biouser") BioUser biouser, Model model, HttpServletRequest request, HttpSession session) throws Exception {

		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		if (session.getAttribute("user_login_name") != null && access == 1) {
			if (biouser.getChkFP().trim() != null) {
				String fingerPrint = null;

				fingerPrint = biouser.getChkFP().trim();
				String deviceType = biouser.getDeviceType().trim();

				request.getSession().setAttribute("sessionanumber", biouser.getTxtAadhaarNo());

				request.getSession().setAttribute("txtusername", biouser.getTxtusername());
				request.getSession().setAttribute("txtuseremail", biouser.getTxtuseremail());

				request.getSession().setAttribute("fingertype", fingerPrint);

				request.getSession().setAttribute("devicetype", deviceType);

				if (fingerPrint.contains("FMR")) {

					return "startekBFD220.html";

				}
				if (fingerPrint.contains("BIOFMR")) {
					return "startek220.html";
				}
				if (fingerPrint.contains("TWOFINGER")) {

					return "startekTWO220.html";
				}

			}

			return "startekError.html";
		} else {
			return "redirect:/login.html";

		}

	}

	/**
	 * Biomatric Success Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/biomatricSuccess", method = RequestMethod.GET)
	public ModelAndView biomatricSuccess(Model model, HttpSession session) throws Exception {
		String propFilePath = "";
		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		if (session.getAttribute("user_login_name") != null && access == 1) {
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name") + "Status::Successfull");
			return new ModelAndView("biomatricSuccess");
		} else {
			return new ModelAndView("redirect:/login.html");

		}

	}

	/**
	 * Biomatric Error.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/biomatricError", method = RequestMethod.GET)
	public ModelAndView biomatricError(Model model, HttpSession session) throws Exception {
		String propFilePath = "";
		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		if (session.getAttribute("user_login_name") != null && access == 1) {

			return new ModelAndView("biomatricError");
		} else {
			return new ModelAndView("redirect:/login.html");
		}

	}

	@RequestMapping(value = "/startekbioAuthentication", method = { RequestMethod.POST, RequestMethod.GET })
	public @ResponseBody String startekbioAuthentication(@RequestParam(value = "baseimagecode", required = true) String baseimagecode, @RequestParam(value = "aadhaarnumber", required = true) String aadhaarnumber, Model model, HttpSession session, HttpServletRequest request) throws Exception {

		Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
		Log.aua.info("User Login For Demo Auth ::" + session.getAttribute("user_login_name"));

		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		String response_time = "", request_time = "", matchingvalue = "";

		DateFormat dateFormatt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
		Date reqdatee = new Date();
		request_time = dateFormatt.format(reqdatee);
		if (session.getAttribute("user_login_name") != null && access == 1) {

			Date connectionStartTime = null;

			BufferedWriter out = null;
			BufferedWriter out1 = null;
			FileWriter fstream = null;
			FileWriter fstream1 = null;
			Calendar c = Calendar.getInstance();
			long nonce = c.getTimeInMillis();

			String verify_name = session.getAttribute("user_login_name").toString().trim();

			String flocation = "", fpostalcode = "", fcity = "";
			String orgip = AUAUtilities.getClientIpAddr(request);

			Properties properties = new Properties();

			ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
			properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

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

				Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
				Log.aua.info("Error Message::" + e1);
				e1.printStackTrace();

			}

			IpassCustomBase64 piddecodestring = new IpassCustomBase64();

			org.jsoup.nodes.Document doc2 = Jsoup.parse(baseimagecode, "", Parser.xmlParser());
			udc = doc2.getElementsByTag("DeviceInfo").attr("dc").trim();

			if (StringUtils.isNotEmpty(udc)) {

				int isValidDevice = bioDAO.isValidDevice(udc);

				if (isValidDevice == 1) {

					String pidXML = baseimagecode;

					String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();
					AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()));

					DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
					Date reqdate = new Date();
					request_time = dateFormat.format(reqdate);

					try {

						pro.setUid(aadhaarnumber.trim());
						pro.setAc(PREAUAProperties.getUidai_aua_code());
						pro.setSa(PREAUAProperties.getUidai_subaua_code());
						pro.setRc(RcType.Y);
						pro.setTid(TidType.registered);
						pro.setLk(PREAUAProperties.getUidai_bio_license_key());
						pro.setTxn(utransactionId);
						pro.setRDRespone(pidXML, "FMR", false, false, false, false, false, "UDC0001");
						String requestXml = "";

						try {

							requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

							String responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);

							try {

								AuthRes res = pro.parse(responseXml);

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								if (responseXml.startsWith("<Error>")) {

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failiur" + "::" + "ResponseTime::" + response_time + "::Status Code:" + res.getErr() + "::ResTranscation id:" + res.getTxn());

									request.getSession().setAttribute("message", "Authentication Failure");
									request.getSession().setAttribute("Error", res.getErr());
									return "biomatricsDefaultError.html";

								}

								if (res.getRet() == AuthResult.Y) {

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + res.getTxn());

									request.getSession().setAttribute("biotransactionnm", res.getTxn());
									request.getSession().setAttribute("Code", res.getCode());
									request.getSession().setAttribute("message", "Authentication Success");

									Verification veri = null;
									veri = new Verification();
									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setUDC_CODE(udc);
									veri.setAUTH_TYPE("BIOAUTH");

									veri.setMESSAGE("Authentication Success");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));
									veri.setTRANSACTION_ID(res.getTxn());
									veri.setSERVER_RESPONSE_ON(res.getTs());
									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setCOUNTRY(flocation);
									veri.setIPADDRESS(orgip);
									veri.setCITY(fcity);
									veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
									veri.setSTATUS(1);
									veri.setSTATUS_DESCRIPTION("Authentication Success");
									veri.setREFERENCE_NUMBER(res.getCode());
									veri.setREQUESTED_BY(verify_name);
									veri.setCONSENT(1);
									veri.setENV_TYPE("PREPROD");
									veri.setAPI_NAME("CDSL");
									int verificationid = verificationDAO.save(veri);

									return "biomatricSuccess.html";

								} else {

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + res.getCode() + "::ResTranscation id:" + res.getTxn());

									request.getSession().setAttribute("biotransactionnm", res.getTxn());
									request.getSession().setAttribute("ErrorCode", res.getErr());
									request.getSession().setAttribute("message", "Authentication Failure");

									Verification veri = null;
									veri = new Verification();

									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setUDC_CODE(udc);
									veri.setAUTH_TYPE("BIOAUTH");
									veri.setMESSAGE("Authentication Failure");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));
									veri.setTRANSACTION_ID(res.getTxn());
									veri.setSERVER_RESPONSE_ON(res.getTs());
									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setERROR_CODE(res.getErr());
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

									outputresults.put("error", "1");

									if (res.getErr().contains("300")) {

										outputresults.put("scode", 2);
										outputresults.put("message", "Biometric Mismatch and placed finger correctly");

										return outputresults.toString();

									} else if (res.getErr().contains("998")) {
										outputresults.put("scode", 3);
										outputresults.put("message", "Aadhaar number is not valid. please check your aadhaar number");

										return "biomatricError.html";

									} else {

										outputresults.put("scode", 1);
										outputresults.put("message", "Authentication Failure");

										return "biomatricError.html";

									}

								}

							} catch (AsaServerException ex) {

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");
								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE(((Element) doc).select("Code").text());
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setREFERENCE_NUMBER(doc.select("txn").text());
								veri.setSTATUS_DESCRIPTION(ex.getMessage());
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								veri.setCONSENT(1);
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";
							} catch (XMLParsingException ex) {

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");
								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE(((Element) doc).select("Code").text());
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setREFERENCE_NUMBER(doc.select("txn").text());
								veri.setSTATUS_DESCRIPTION(ex.getMessage());
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								veri.setCONSENT(1);
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";

							} catch (InvalidResponseException ex) {
								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");

								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE(((Element) doc).select("Code").text());
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setREFERENCE_NUMBER(doc.select("txn").text());
								veri.setSTATUS_DESCRIPTION(ex.getMessage());
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";

							} catch (UidaiSignatureVerificationFailedException ex) {
								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");

								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE(((Element) doc).select("Code").text());
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setREFERENCE_NUMBER(doc.select("txn").text());
								veri.setSTATUS_DESCRIPTION(ex.getMessage());
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								veri.setCONSENT(1);
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";

							} catch (Exception ex) {

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								if (ex.getMessage().contentEquals("Invalid uid")) {

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

									Verification veri = null;
									veri = new Verification();
									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setUDC_CODE(udc);
									veri.setAUTH_TYPE("BIOAUTH");

									veri.setMESSAGE("Authentication Failure");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));
									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setERROR_CODE("998");
									veri.setCOUNTRY(flocation);
									veri.setIPADDRESS(orgip);
									veri.setCITY(fcity);
									veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
									veri.setSTATUS(0);
									veri.setSTATUS_DESCRIPTION("Invalid Aadhaar Number");
									veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
									veri.setCONSENT(1);
									veri.setENV_TYPE("PREPROD");
									veri.setAPI_NAME("CDSL");
									int verificationid = verificationDAO.save(veri);

									outputresults.put("scode", 1);
									outputresults.put("message", "Authentication Failure");

									return "biomatricError.html";

								} else {

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

									Verification veri = null;
									veri = new Verification();
									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setUDC_CODE(udc);
									veri.setAUTH_TYPE("BIOAUTH");

									veri.setMESSAGE("Authentication Failure");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));

									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setERROR_CODE("");
									veri.setCOUNTRY(flocation);
									veri.setIPADDRESS(orgip);
									veri.setCITY(fcity);
									veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
									veri.setSTATUS(0);
									veri.setSTATUS_DESCRIPTION("ASA server down!Please contact technical team");
									veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
									veri.setCONSENT(1);
									veri.setENV_TYPE("PREPROD");
									veri.setAPI_NAME("CDSL");

									int verificationid = verificationDAO.save(veri);

									outputresults.put("scode", 1);
									outputresults.put("message", "Authentication Failure");

									return "biomatricError.html";
								}
							}

						} catch (Exception ex) {

							DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
							Date reqdate2 = new Date();
							response_time = dateFormat2.format(reqdate2);
							JSONObject outputresults = new JSONObject();

							if (ex.getMessage().contentEquals("Invalid uid")) {

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");

								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE("998");
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setSTATUS_DESCRIPTION("Invalid Aadhaar Number");
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								veri.setCONSENT(1);
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";

							} else {

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

								Verification veri = null;
								veri = new Verification();
								veri.setAPI_NAME("2.0");
								veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
								veri.setUDC_CODE(udc);
								veri.setAUTH_TYPE("BIOAUTH");

								veri.setMESSAGE("Authentication Failure");
								veri.setUID(Long.parseLong(aadhaarnumber.toString()));

								veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
								veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
								veri.setERROR_CODE("");
								veri.setCOUNTRY(flocation);
								veri.setIPADDRESS(orgip);
								veri.setCITY(fcity);
								veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
								veri.setSTATUS(0);
								veri.setSTATUS_DESCRIPTION("ASA server down!Please contact technical team");
								veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								veri.setCONSENT(1);
								veri.setENV_TYPE("PREPROD");
								veri.setAPI_NAME("CDSL");
								int verificationid = verificationDAO.save(veri);

								outputresults.put("scode", 1);
								outputresults.put("message", "Authentication Failure");

								return "biomatricError.html";
							}

						}

					} catch (NullPointerException ex) {

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);
						JSONObject outputresults = new JSONObject();

						Verification veri = null;
						veri = new Verification();
						veri.setAPI_NAME("2.0");
						veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
						veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
						veri.setUDC_CODE(udc);
						veri.setAUTH_TYPE("BIOAUTH");

						veri.setMESSAGE("Authentication Failure");
						veri.setUID(Long.parseLong(aadhaarnumber.toString()));
						veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
						veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
						veri.setERROR_CODE("");
						veri.setCOUNTRY(flocation);
						veri.setIPADDRESS(orgip);
						veri.setCITY(fcity);
						veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
						veri.setSTATUS(0);
						veri.setSTATUS_DESCRIPTION("Invalid pid xml");
						veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
						veri.setCONSENT(1);
						veri.setENV_TYPE("PREPROD");
						veri.setAPI_NAME("CDSL");
						int verificationid = verificationDAO.save(veri);

						outputresults.put("scode", 1);
						outputresults.put("message", "Authentication Failure");

						return "biomatricError.html";

					}

				} else {
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Device Not Whitelisted" + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

					DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
					Date reqdate2 = new Date();
					response_time = dateFormat2.format(reqdate2);
					JSONObject outputresults = new JSONObject();

					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setUDC_CODE(udc);
					veri.setAUTH_TYPE("BIOAUTH");

					veri.setMESSAGE("Authentication Failure");
					veri.setUID(Long.parseLong(aadhaarnumber.toString()));
					veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
					veri.setERROR_CODE("");
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setSTATUS_DESCRIPTION("Device Not Whitelisted");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setAPI_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);

					outputresults.put("scode", 1);
					outputresults.put("message", "Device Not Whitelisted");

					return "biomatricError.html";
				}
			} else {
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Device is not Whitelisted" + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

				DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
				Date reqdate2 = new Date();
				response_time = dateFormat2.format(reqdate2);
				JSONObject outputresults = new JSONObject();

				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setUDC_CODE(udc);
				veri.setAUTH_TYPE("BIOAUTH");

				veri.setMESSAGE("Authentication Failure");
				veri.setUID(Long.parseLong(aadhaarnumber.toString()));
				veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
				veri.setERROR_CODE("");
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Device is not Whitelisted");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setAPI_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				outputresults.put("scode", 1);
				outputresults.put("message", "Device is not Whitelisted");

				return "biomatricError.html";

			}

		}

		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
		Date reqdate = new Date();
		response_time = dateFormat.format(reqdate);
		Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
		Log.aua.info("Response Meta Data Details::Staus Message:Something Went Wrong" + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");
		JSONObject outputresults = new JSONObject();
		outputresults.put("scode", 1);
		outputresults.put("message", "Something Went Wrong");

		return "biomatricError.html";

	}

	@RequestMapping(value = "/startekbfdAuthentication", method = { RequestMethod.POST, RequestMethod.GET })
	public @ResponseBody String startekbfdAuthentication(@RequestParam(value = "baseimagecode", required = true) String baseimagecode, @RequestParam(value = "aadhaarnumber", required = true) String aadhaarnumber, Model model, HttpSession session, HttpServletRequest request) throws Exception {

		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		if (session.getAttribute("user_login_name") != null && access == 1) {

			Date connectionStartTime = null;

			BufferedWriter out = null;
			BufferedWriter out1 = null;
			FileWriter fstream = null;
			FileWriter fstream1 = null;
			Calendar c = Calendar.getInstance();
			long nonce = c.getTimeInMillis();

			String verify_name = session.getAttribute("user_login_name").toString().trim();

			String flocation = "", fpostalcode = "", fcity = "";
			String orgip = AUAUtilities.getClientIpAddr(request);

			String response_time = "", request_time = "", matchingvalue = "";

			DateFormat dateFormatt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
			Date reqdatee = new Date();
			request_time = dateFormatt.format(reqdatee);

			Properties properties = new Properties();

			ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
			properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

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

				Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
				Log.aua.info("Error Message::" + e1);
				e1.printStackTrace();

			}

			String udc = "UDC0001";
			String data = "";
			String fudc = "";
			String snumber = "";

			IpassCustomBase64 piddecodestring = new IpassCustomBase64();

			org.jsoup.nodes.Document doc2 = Jsoup.parse(baseimagecode, "", Parser.xmlParser());
			fudc = doc2.getElementsByTag("DeviceInfo").attr("dc").trim();

			if (fudc.length() != 0) {

				int isValidDevice = bioDAO.isValidDevice(fudc);

				if (isValidDevice == 1) {

					String pidXML = baseimagecode;

					String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();

					BfdProcessor bf = new BfdProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()));

					DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
					Date reqdate = new Date();
					request_time = dateFormat.format(reqdate);

					try {
						List<BfdData> bioCaptures = new ArrayList<BfdData>();
						bioCaptures.add(new BfdData(FingerPosition.RIGHT_THUMB, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.RIGHT_INDEX, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.RIGHT_LITTLE, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.RIGHT_MIDDLE, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.RIGHT_RING, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.LEFT_INDEX, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.LEFT_THUMB, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.LEFT_LITTLE, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.LEFT_MIDDLE, pidXML.getBytes(), 3));
						bioCaptures.add(new BfdData(FingerPosition.LEFT_RING, pidXML.getBytes(), 1));

						bf.setUid(aadhaarnumber.trim());
						bf.setAc(PREAUAProperties.getUidai_aua_code());
						bf.setSa(PREAUAProperties.getUidai_subaua_code());
						bf.setLk(PREAUAProperties.getUidai_bio_license_key());
						bf.setTxn(utransactionId);
						// bf.setHmac(((Element) doc2).select("Hmac").text().getBytes());
						// bf.setTid(TidType.Public);
						// bf.prepareBfdRbdBlock(bioCaptures, "UDC0001",null , "");

						bf.prepareBfdRbdBlock(bioCaptures, "UDC0001", null, "", "");

						String requestXml = "";

						try {

							requestXml = bf.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());
							System.out.println("sanjay1" + requestXml);
							String responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);
							System.out.println("sanjay2" + responseXml);
							try {

								BfdRes res = bf.parse(responseXml);

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								if (responseXml.startsWith("<Error>")) {

									request.getSession().setAttribute("message", "Authentication Failed!");
									request.getSession().setAttribute("Error", res.getErr());
									return "biomatricsDefaultError.html";

								}

								// if (res.ge == AuthResult.Y) {
								//
								// System.out.println("sanjaynegiiiiiii");
								// request.getSession().setAttribute("biotransactionnm", res.getTxn());
								// request.getSession().setAttribute("Code", res.getCode());
								// request.getSession().setAttribute("message", "Authentication Successful");
								//
								// Verification veri = null;
								// veri = new Verification();
								// veri.setAPI_NAME("2.0");
								// veri.setAUA_CODE("0001980000");
								// veri.setSUB_AUA_CODE("0001980000");
								// veri.setUDC_CODE(udc);
								// veri.setAUTH_TYPE("BIOAUTH");
								// veri.setREQUEST_ON(request_time);
								// veri.setRESPONSE_ON(response_time);
								// veri.setMESSAGE("Authentication Success!");
								// veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								// veri.setTRANSACTION_ID(res.getTxn());
								// veri.setSERVER_RESPONSE_ON(res.getTs());
								// veri.setREQUEST_ON(request_time);
								// veri.setRESPONSE_ON(response_time);
								// veri.setCOUNTRY(flocation);
								// veri.setIPADDRESS(orgip);
								// veri.setCITY(fcity);
								// veri.setPINCODE(fpostalcode);
								// veri.setSTATUS(1);
								// veri.setREFERENCE_NUMBER(res.getCode());
								//
								// int verificationid = verificationDAO.save(veri);
								//
								// return "biomatricSuccess.html";
								//
								// }else {
								//
								//
								// request.getSession().setAttribute("biotransactionnm", res.getTxn());
								// request.getSession().setAttribute("ErrorCode", res.getErr());
								// request.getSession().setAttribute("message", "Authentication Failed!");
								//
								// Verification veri = null;
								// veri = new Verification();
								//
								// veri.setAPI_NAME("2.0");
								// veri.setAUA_CODE("0001980000");
								// veri.setAUTH_TYPE("BIOAUTH");
								// veri.setMESSAGE("Authentication Failed!");
								// veri.setUID(Long.parseLong(aadhaarnumber.toString()));
								// veri.setTRANSACTION_ID(res.getTxn());
								// veri.setSERVER_RESPONSE_ON(res.getTs());
								// veri.setREQUEST_ON(request_time);
								// veri.setRESPONSE_ON(response_time);
								// veri.setERROR_CODE(res.getErr());
								// veri.setCOUNTRY(flocation);
								// veri.setIPADDRESS(orgip);
								// veri.setCITY(fcity);
								// veri.setPINCODE(fpostalcode);
								// veri.setSTATUS(0);
								// veri.setREFERENCE_NUMBER(res.getCode());
								// veri.setSTATUS_DESCRIPTION("statusfaild");
								// veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
								// int verificationid = verificationDAO.save(veri);
								//
								// outputresults.put("error","1");
								//
								// if (res.getErr().contains("300")) {
								//
								// outputresults.put("scode", 2);
								// outputresults.put("message", "Biometric Mismatch and placed finger correctly");
								// Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::"
								// + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::"
								// + request_time + "Timestamp::" + res.getTs());
								// return outputresults.toString();
								//
								// } else if (res.getErr().contains("998")) {
								// outputresults.put("scode", 3);
								// outputresults.put("message", "Aadhaar number is not valid. please check your aadhaar number");
								// Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::"
								// + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::"
								// + request_time + "Timestamp::" + res.getTs());
								// return "biomatricError.html";
								//
								// } else {
								//
								// outputresults.put("scode", 1);
								// outputresults.put("message", "Authentication Failed!");
								// Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::"
								// + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::"
								// + request_time + "Timestamp::" + res.getTs());
								// return "biomatricError.html";
								//
								// }
								//
								//
								//
								// }

							} catch (Exception ex) {
							}

						} catch (Exception ex) {
						}

					} catch (Exception ex) {
					}

				}
			}

		}
		return null;

	}

	/**
	 * Biomatric Image Captured Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/startekTWO220", method = RequestMethod.GET)
	public ModelAndView startekTWO220(Model model, HttpSession session) throws Exception {

		System.out.println("nnnegi");
		String propFilePath = "";

		PREAUAProperties.load();
		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
		Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));
		if (session.getAttribute("user_login_name") != null && access == 1) {
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name") + "Status::Successfull");
			return new ModelAndView("startekTWO220");
		} else {
			return new ModelAndView("redirect:/login.html");

		}

	}

	/**
	 * Two Finger Image Capture Request.
	 *
	 * @param biouser
	 *            the biouser
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @param request
	 *            the request
	 * @return the string
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/twofingerAuthentication", method = { RequestMethod.POST, RequestMethod.GET })
	public @ResponseBody String twobioAuthentication(@RequestParam(value = "baseimagecode", required = true) String baseimagecode, @RequestParam(value = "aadhaarnumber", required = true) String aadhaarnumber, Model model, HttpSession session, HttpServletRequest request) throws Exception {

		PREAUAProperties.load();

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);

		if (session.getAttribute("user_login_name") != null && access == 1) {

			Date connectionStartTime = null;

			BufferedWriter out = null;
			BufferedWriter out1 = null;
			FileWriter fstream = null;
			FileWriter fstream1 = null;
			Calendar c = Calendar.getInstance();
			long nonce = c.getTimeInMillis();

			String verify_name = session.getAttribute("user_login_name").toString().trim();

			String flocation = "", fpostalcode = "", fcity = "";
			String orgip = AUAUtilities.getClientIpAddr(request);

			String response_time = "", request_time = "", matchingvalue = "";

			DateFormat dateFormatt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
			Date reqdatee = new Date();
			request_time = dateFormatt.format(reqdatee);

			Properties properties = new Properties();

			ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
			properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

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

				Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
				Log.aua.info("Error Message::" + e1);
				e1.printStackTrace();

			}

			String udc = "UDC0001";
			String data = "";
			String fudc = "";
			String snumber = "";

			IpassCustomBase64 piddecodestring = new IpassCustomBase64();

			org.jsoup.nodes.Document doc2 = Jsoup.parse(baseimagecode, "", Parser.xmlParser());
			fudc = doc2.getElementsByTag("DeviceInfo").attr("dc").trim();

			if (fudc.length() != 0) {

				int isValidDevice = bioDAO.isValidDevice(fudc);

				if (isValidDevice == 1) {

					String pidXML = baseimagecode;

					String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();
					AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()));

					DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
					Date reqdate = new Date();
					request_time = dateFormat.format(reqdate);

					try {

						pro.setUid(aadhaarnumber.trim());
						pro.setAc(PREAUAProperties.getUidai_aua_code());
						pro.setSa(PREAUAProperties.getUidai_subaua_code());
						pro.setRc(RcType.Y);
						pro.setTid(TidType.registered);
						pro.setLk(PREAUAProperties.getUidai_bio_license_key());
						pro.setTxn(utransactionId);
						pro.setRDRespone(pidXML, "FMR", false, false, false, false, false, "UDC0001");

						String requestXml = "";

						try {

							requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());
							System.out.println("sanjay1" + requestXml);
							String responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);
							System.out.println("sanjay2" + responseXml);
							try {

								AuthRes res = pro.parse(responseXml);

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);
								JSONObject outputresults = new JSONObject();

								if (responseXml.startsWith("<Error>")) {

									request.getSession().setAttribute("message", "Authentication Failed!");
									request.getSession().setAttribute("Error", res.getErr());
									return "biomatricsDefaultError.html";

								}

								if (res.getRet() == AuthResult.Y) {

									System.out.println("sanjaynegiiiiiii");
									request.getSession().setAttribute("biotransactionnm", res.getTxn());
									request.getSession().setAttribute("Code", res.getCode());
									request.getSession().setAttribute("message", "Authentication Successful");

									Verification veri = null;
									veri = new Verification();
									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setUDC_CODE(udc);
									veri.setAUTH_TYPE("BIOAUTH");

									veri.setMESSAGE("Authentication Success");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));
									veri.setTRANSACTION_ID(res.getTxn());
									veri.setSERVER_RESPONSE_ON(res.getTs());
									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setCOUNTRY(flocation);
									veri.setIPADDRESS(orgip);
									veri.setCITY(fcity);
									veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
									veri.setSTATUS(1);
									veri.setENV_TYPE("PREPROD");
									veri.setAPI_NAME("CDSL");
									veri.setREFERENCE_NUMBER(res.getCode());

									int verificationid = verificationDAO.save(veri);

									return "biomatricSuccess.html";

								} else {

									request.getSession().setAttribute("biotransactionnm", res.getTxn());
									request.getSession().setAttribute("ErrorCode", res.getErr());
									request.getSession().setAttribute("message", "Authentication Failed!");

									Verification veri = null;
									veri = new Verification();

									veri.setAPI_NAME("2.0");
									veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
									veri.setAUTH_TYPE("BIOAUTH");
									veri.setMESSAGE("Authentication Failed!");
									veri.setUID(Long.parseLong(aadhaarnumber.toString()));
									veri.setTRANSACTION_ID(res.getTxn());
									veri.setSERVER_RESPONSE_ON(res.getTs());
									veri.setREQUEST_ON(new Timestamp(dateFormat2.parse(request_time).getTime()));
									veri.setRESPONSE_ON(new Timestamp(dateFormat2.parse(response_time).getTime()));
									veri.setERROR_CODE(res.getErr());
									veri.setCOUNTRY(flocation);
									veri.setIPADDRESS(orgip);
									veri.setCITY(fcity);
									veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
									veri.setSTATUS(0);
									veri.setREFERENCE_NUMBER(res.getCode());
									veri.setSTATUS_DESCRIPTION("statusfaild");
									veri.setENV_TYPE("PREPROD");
									veri.setAPI_NAME("CDSL");
									veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
									int verificationid = verificationDAO.save(veri);

									outputresults.put("error", "1");

									if (res.getErr().contains("300")) {

										outputresults.put("scode", 2);
										outputresults.put("message", "Biometric mismatch and placed finger correctly");
										Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::" + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::" + request_time + "Timestamp::" + res.getTs());
										return outputresults.toString();

									} else if (res.getErr().contains("998")) {
										outputresults.put("scode", 3);
										outputresults.put("message", "Aadhaar number is not valid. please check your aadhaar number");
										Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::" + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::" + request_time + "Timestamp::" + res.getTs());
										return "biomatricError.html";

									} else {

										outputresults.put("scode", 1);
										outputresults.put("message", "Authentication Failed!");
										Log.aua.info("Response Error:" + "Aadhaar Number::" + aadhaarnumber.trim() + "Error::" + res.getErr() + "TransactionId::" + res.getTxn() + "RequestTime::" + request_time + "Timestamp::" + res.getTs());
										return "biomatricError.html";

									}

								}

							} catch (Exception ex) {
							}

						} catch (Exception ex) {
						}

					} catch (Exception ex) {
					}

				}
			}

		}
		return null;

	}

}