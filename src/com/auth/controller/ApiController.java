package com.auth.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.auth.bean.normalAuthDetails;
import com.auth.bean.subAua;
import com.auth.dao.NormalDetailsDAO;
import com.auth.dao.PersonalDAO;
import com.auth.dao.ResidentialDAO;
import com.auth.dao.SubAuaDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.service.DemoService;
import com.auth.util.AUAUtilities;
import com.auth.util.DateValidator;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
import com.auth.util.Util;
import com.auth.util.authData;
import com.auth.util.paramValidation;
import com.ecs.asa.processor.AuthProcessor;
import com.ecs.asa.processor.AuthProcessor.RcType;
import com.ecs.asa.processor.AuthProcessor.TidType;
import com.ecs.asa.utils.HttpConnector;
import com.ecs.aua.pidgen.support.DemoAuthData;
import com.ecs.exceptions.AsaServerException;
import com.ecs.exceptions.InvalidResponseException;
import com.ecs.exceptions.UidaiSignatureVerificationFailedException;
import com.ecs.exceptions.XMLParsingException;
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;

/**
 * The Class ApiController.
 */
@Controller
public class ApiController {

	@Autowired
	private NormalDetailsDAO normaldetaildao;

	@Autowired
	private VerificationDAO verificationDAO;

	/** The user login DAO. */
	@Autowired
	private UserLoginDAO userLogindao;

	/** The personal DAO. */
	@Autowired
	private PersonalDAO personalDAO;

	/** The residential DAO. */
	@Autowired
	private ResidentialDAO residentialDAO;

	@Autowired
	private DemoService demoService;

	@Autowired
	private SubAuaDAO subauadao;

	/**
	 * Demographic api authentication.
	 *
	 * @param username
	 *            the username
	 * @param password
	 *            the password
	 * @param request
	 *            the request
	 * @param session
	 *            the session
	 * @param model
	 *            the model
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */
	@RequestMapping(value = "/demographic", method = { RequestMethod.POST, RequestMethod.GET })
	public ModelAndView demographicApiAuthentication(@RequestBody String jsondata, HttpServletRequest request, HttpServletResponse response, HttpSession session, Model model) throws Exception {

		PREAUAProperties.load();
		Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
		Properties propertiesquery = new Properties();
		Boolean enryptedFlag = true;
		Map<String, String> mapheader = new HashMap<String, String>();
		Enumeration headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = request.getHeader(key);
			mapheader.put(key, value);

		}

		// Global Variables
		String auth_data = "", aadharcardnumber = "", verifyby = "", token = "", udc = "";

		/** RequestTime Set **/
		String request_time = "";
		String subAuaCode = "";
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
		Date reqdate = new Date();
		request_time = dateFormat.format(reqdate);

		/** Generating Unique transactionid **/

		String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();

		if (StringUtils.isEmpty(mapheader.get("client_id"))) {
			enryptedFlag = false;
		}
		if (request.getMethod().toUpperCase().contains("POST")) {

			if (mapheader.get("content-type").trim().equalsIgnoreCase("application/json")) {

				/** Request parameter checked */
				ClassLoader classloadererrorquery = Thread.currentThread().getContextClassLoader();
				propertiesquery.load(new FileInputStream(new File(classloadererrorquery.getResource("parameter.properties").getFile())));
				ClassLoader classLoader = getClass().getClassLoader();
				Properties properties = new Properties();
				/** Aadhaar errorcode checked **/
				ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
				properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

				String flocation = "", fpostalcode = "", fcity = "";
				String orgip = AUAUtilities.getClientIpAddr(request);
				/** Ipaddress captured **/
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
					Log.aua.info("Error Message::" + e1);
					e1.printStackTrace();

				}

				try {

					if (enryptedFlag) {

						Log.aua.info("User Logged As ::" + mapheader.get("client_id").trim());
						verifyby = mapheader.get("client_id").trim();
						normalAuthDetails urldata = normaldetaildao.getOneById(verifyby);

						String rclientid = "";

						if (StringUtils.isNotEmpty(urldata.getClient_id())) {

							subAua subauaDetails = subauadao.getSubAUA(mapheader.get("subauacode"));
							if (subauaDetails == null) {
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
								Log.aua.info("User:::" + mapheader.get("subauacode") + "::Invalid SubAUA");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("demographicauth");
							} else {

								subAuaCode = subauaDetails.getSubaua_code().trim();

							}

							rclientid = urldata.getClient_id();
							token = urldata.getAut_token();
							auth_data = AUAUtilities.doDecrypt(token, jsondata.trim());
							if (auth_data.contentEquals("A900")) {

								String response_time = "";
								DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
								Date rreqdatee1 = new Date();
								response_time = rdateFormatt1.format(rreqdatee1);

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:Invalid encryption" + "::" + "ResponseTime::" + response_time + "::Status Code:A114" + "::ResTranscation id:" + "");

								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A114").add("Message", "Invalid encryption.");
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("demographicauth");
							}

						} else {

							String response_time = "";
							DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date rreqdatee1 = new Date();
							response_time = rdateFormatt1.format(rreqdatee1);
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:You are not authorized to make such request. Please contact system administrator" + "::" + "ResponseTime::" + response_time + "::Status Code:A102" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A102").add("Message", "You are not authorized to make such request. Please contact system administrator.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("demographicauth");
						}

					} else {

						if (StringUtils.isNotEmpty(mapheader.get("username")) && StringUtils.isNotEmpty(mapheader.get("password"))) {
							boolean isDemoValidUser = subauadao.isValidClient(mapheader.get("username"), mapheader.get("password"));

							if (isDemoValidUser == false) {
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
								Log.aua.info("User:::" + mapheader.get("username") + "::Invalid user");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A102").add("Message", "You are not authorized to make such request. Please contact system administrator.");

								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("demographicauth");

							} else {
								subAua subauaDetails = subauadao.getSubAUA(mapheader.get("username"));

								if (subauaDetails == null) {
									response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
									Log.aua.info("User:::" + mapheader.get("subauacode") + "::Invalid SubAUA");
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("demographicauth");
								} else {
									subAuaCode = subauaDetails.getSubaua_code().trim();

								}
							}

							auth_data = jsondata.trim();
							verifyby = mapheader.get("username").trim();
							Log.aua.info("User Logged As ::" + mapheader.get("username").trim());
						} else {

							String response_time = "";
							DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date reqdate2 = new Date();
							response_time = dateFormat2.format(reqdate2);
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Bad request. Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad request. Please check your headers.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("demographicauth");
						}
					}
					// End process

					Boolean isValid = true;
					Boolean isdobtypeValid = false;
					Boolean isdobValid = true;
					Boolean isGender = false;
					Boolean isMobile = false;
					Boolean isEmail = false;
					Boolean isAadhaar = false;
					Boolean isValidRequest = true;
					Boolean isValidPin = true;

					int authBlock = 0;
					DemoAuthData authdata = new DemoAuthData();
					authData auth = new authData();
					String fkey = "";

					Map map = new HashMap();
					JSONObject resobj = new JSONObject(auth_data);

					Iterator<?> keys = resobj.keys();
					while (keys.hasNext()) {
						fkey = (String) keys.next();
						map.put(fkey, resobj.get(fkey).toString());

						if (propertiesquery.getProperty(fkey) != null) {

							/** Checking valid aadhaar number **/
							paramValidation pval = new paramValidation();
							if (fkey.equalsIgnoreCase("aadhaarnumber")) {
								isAadhaar = pval.isAaadharValid(resobj.get("aadhaarnumber").toString());

							}

							if (fkey.equalsIgnoreCase("dob")) {
								isdobValid = new DateValidator().validate(resobj.get("dob").toString());

							}
							if (fkey.equalsIgnoreCase("pincode")) {

								isValidPin = new Util().isValidPin(resobj.get("pincode").toString());

							}

							/** Checking valid dobtype **/
							if (fkey.equalsIgnoreCase("dob_type")) {

								isdobtypeValid = pval.isDobTypeValid(resobj.get("dob_type").toString());

							} else {
								isdobtypeValid = true;
							}

							/** Checking valid gender **/
							if (fkey.equalsIgnoreCase("gender")) {

								isGender = pval.isgenderValid(resobj.get("gender").toString());
							} else {
								isGender = true;
							}
							/** Checking valid mobile number **/
							if (fkey.equalsIgnoreCase("mobileno")) {
								isMobile = pval.ismobileValid(resobj.get("mobileno").toString());

							} else {
								isMobile = true;
							}
							/** Checking valid email **/
							if (fkey.equalsIgnoreCase("email")) {
								isEmail = pval.isemailValid(resobj.get("email").toString());
							} else {
								isEmail = true;
							}

							authdata = auth.setValueAt(fkey.trim(), (resobj.get(fkey).toString()).trim());
							isValid = true;

						} else {
							isValid = false;
							break;

						}

					}

					if (isValid == true) {

						// ###Check the aadhaar number valid or not##/

						if (isAadhaar == true) {

							if (isdobtypeValid == true) {

								if (isGender == true) {

									if (isMobile == true) {

										if (isEmail == true) {

											if (isdobValid == true) {

												if (isValidPin == true)

												{

													aadharcardnumber = resobj.get("aadhaarnumber").toString().trim();

													AuthProcessor pro = null;
													pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()), PREAUAProperties.readAll(PREAUAProperties.getUidai_signing_cert()));

													pro.setUid(aadharcardnumber.toString().trim());
													pro.setAc(PREAUAProperties.getUidai_aua_code());
													pro.setSa(subAuaCode);
													pro.setRc(RcType.Y);
													pro.setTid(TidType.None);
													pro.setLk(PREAUAProperties.getUidai_license_key());
													pro.setTxn(utransactionId);

													pro.prepareDemographicPidBlock(authdata, "AUT122333");

													String requestXml = "";
													String responseXml = "";

													try {

														requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

														try {

															responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);
															
															System.out.println("sanjay1"+responseXml);
															
															/** Response Time Set **/
															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);

															AuthRes authres = pro.parse(responseXml);

															/** success response checked **/
															if (authres.getRet() == AuthResult.Y) {

																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:A200" + "::ResTranscation id:" + authres.getTxn());
																response.setStatus(HttpServletResponse.SC_OK);

																JsonObjectBuilder value2 = Json.createObjectBuilder();
																value2.add("StatusCode", "A200");
																value2.add("Uid", Util.maskCardNumber(aadharcardnumber));
																value2.add("TransactionID", authres.getTxn());
																value2.add("Message", "Authentication Success.");
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());

																/**** Saving The Data To Call Service Method *****/
																demoService.saveDemoAuth(authres, request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

															}
															/*** Failed Response Handle ***/
															else {

																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:" + properties.getProperty(authres.getErr()) + "::" + "ResponseTime::" + response_time + "::Status Code:" + authres.getErr() + "::ResTranscation id:" + authres.getTxn());
																response.setStatus(HttpServletResponse.SC_OK);
																JsonObjectBuilder value2 = Json.createObjectBuilder();
																value2.add("StatusCode", "A201");
																value2.add("Uid", Util.maskCardNumber(aadharcardnumber));
																value2.add("TransactionID", authres.getTxn());
																value2.add("Error", authres.getErr());
																value2.add("Message", properties.getProperty(authres.getErr()));
																JsonObject dataJsonObject = value2.build();

																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
																/**** Saving The Data To Call Service Method *****/

																demoService.saveDemoAuth(authres, request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

															}
														} /** Failed Parsed XML **/
														catch (XMLParsingException ex) {

															response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);
															org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
															demoService.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

															JsonObjectBuilder value2 = Json.createObjectBuilder();
															value2.add("StatusCode", "A212");
															value2.add("Error", ((Element) doc).select("Code").text());
															value2.add("Message", ex.getMessage());
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														} /** ASA server through exception **/
														catch (AsaServerException ex) {

															if (ex.getCode().contentEquals("ASA002")) {

																String response_time = "";
																DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
																Date reqdate2 = new Date();
																response_time = dateFormat2.format(reqdate2);
																demoService.saveExceptionDemo(ex.getCode(), ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);
																response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
																Log.aua.info("User:::" + mapheader.get("subauacode") + "::Invalid SubAUA");
																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A113").add("Message", "AUA configuration not found. Please contact system administrator.");

																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", dataJsonObject);
																return new ModelAndView("demographicauth");
															} else {
																response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
																String response_time = "";
																DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
																Date reqdate2 = new Date();
																response_time = dateFormat2.format(reqdate2);

																demoService.saveExceptionDemo(ex.getCode(), ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ex.getCode() + "::ResTranscation id:" + "");

																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A211").add("Error", ex.getCode()).add("Message", ex.getMessage());
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", dataJsonObject);
															}

														} catch (InvalidResponseException ex) {
															response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);
															org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

															demoService.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A213").add("Error", ((Element) doc).select("Code").text()).add("Message", ex.getMessage());
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														} catch (UidaiSignatureVerificationFailedException ex) {

															response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);
															org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

															demoService.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");
															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A214").add("Error", ((Element) doc).select("Code").text()).add("Message", ex.getMessage());
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														} catch (Exception e) {

															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);

															if (e.getMessage().contentEquals("Invalid uid")) {

																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");
																demoService.saveExceptionDemo("998", e.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);
																response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", dataJsonObject);

															} else {
																response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A217" + "::ResTranscation id:" + "");
																// demoService.saveExceptionDemo("A216", e.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);
																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", dataJsonObject);

															}

														}
													} catch (Exception ex) {

														String response_time = "";
														DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
														Date reqdate2 = new Date();
														response_time = dateFormat2.format(reqdate2);
														if (ex.getMessage().contentEquals("Invalid uid")) {
															response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");
															demoService.saveExceptionDemo("998", ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);
															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														} else {

															response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A217" + "::ResTranscation id:" + "");
															demoService.saveExceptionDemo("A217", ex.getMessage(), request_time, response_time, flocation, orgip, fcity, fpostalcode, verifyby, subAuaCode, map);
															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														}

													}

												} else {
													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);
													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:Email address is invalid" + "::" + "ResponseTime::" + response_time + "::Status Code:A120" + "::ResTranscation id:" + "");

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A131").add("Message", "Pincode is invalid.");
													response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("demographicauth");
												}

											} else {
												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);
												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:Email address is invalid" + "::" + "ResponseTime::" + response_time + "::Status Code:A120" + "::ResTranscation id:" + "");

												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A130").add("Message", "Dob is invalid.");
												response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("demographicauth");
											}

										} else {
											String response_time = "";
											DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
											Date reqdate2 = new Date();
											response_time = dateFormat2.format(reqdate2);
											Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
											Log.aua.info("Response Meta Data Details::Staus Message:Email address is invalid" + "::" + "ResponseTime::" + response_time + "::Status Code:A120" + "::ResTranscation id:" + "");

											JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A120").add("Message", "Email address is invalid.");
											response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
											JsonObject dataJsonObject = value2.build();
											model.addAttribute("model", dataJsonObject);
											return new ModelAndView("demographicauth");
										}

									} else {

										String response_time = "";
										DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
										Date reqdate2 = new Date();
										response_time = dateFormat2.format(reqdate2);

										Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
										Log.aua.info("Response Meta Data Details::Staus Message:Mobile number is invalid" + "::" + "ResponseTime::" + response_time + "::Status Code:A121" + "::ResTranscation id:" + "");
										JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A121").add("Message", "Mobile number is invalid.");
										response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
										JsonObject dataJsonObject = value2.build();
										model.addAttribute("model", dataJsonObject);
										return new ModelAndView("demographicauth");
									}

								} else {

									String response_time = "";
									DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate2 = new Date();
									response_time = dateFormat2.format(reqdate2);

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Gender format is not correct" + "::" + "ResponseTime::" + response_time + "::Status Code:A122" + "::ResTranscation id:" + "");
									response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A122").add("Message", "Gender format is not correct.");

									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("demographicauth");

								}

							} else {

								String response_time = "";
								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:dob type format is not correct" + "::" + "ResponseTime::" + response_time + "::Status Code:A123" + "::ResTranscation id:" + "");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A123").add("Message", "dob type format is not correct.");
								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("demographicauth");
							}

						} else {

							String response_time = "";
							DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date reqdate2 = new Date();
							response_time = dateFormat2.format(reqdate2);

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Aadhaar Number should be of 12 digits" + "::" + "ResponseTime::" + response_time + "::Status Code:A110" + "::ResTranscation id:" + "");
							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A110").add("Message", "Aadhaar Number should be of 12 digits.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);

						}

					} else {

						String response_time = "";
						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + utransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:Please check the parameter" + "::" + "ResponseTime::" + response_time + "::Status Code:A125" + "::ResTranscation id:" + "");
						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A125").add("Message", "Please check the parameter.");

						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);

					}

				} catch (JSONException e) {

					String response_time = "";
					DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
					Date reqdate2 = new Date();
					response_time = dateFormat2.format(reqdate2);

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Invalid Json" + "::" + "ResponseTime::" + response_time + "::Status Code:A106" + "::ResTranscation id:" + "");
					// Demo log

					response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
					JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A106").add("Message", "Invalid Json.");
					JsonObject dataJsonObject = value2.build();
					model.addAttribute("model", dataJsonObject);

				} catch (Exception ex) {

					String response_time = "";
					DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
					Date reqdate2 = new Date();
					response_time = dateFormat2.format(reqdate2);

					if (ex.getMessage().contains("Cannot open connection")) {

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:There is something technical issue! Please contact support team" + "::" + "ResponseTime::" + response_time + "::Status Code:A217" + "::ResTranscation id:" + "");

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);

					} else {

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:There is something technical issue! Please contact support team" + "::" + "ResponseTime::" + response_time + "::Status Code:A217" + "::ResTranscation id:" + "");

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);
					}

				}

			} else {

				String response_time = "";
				DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date rreqdatee1 = new Date();
				response_time = rdateFormatt1.format(rreqdatee1);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Bad Request! Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad Request. Please check your headers.");
				JsonObject dataJsonObject = value2.build();
				model.addAttribute("model", dataJsonObject);
				return new ModelAndView("demographicauth");

			}

		} else {

			String response_time = "";
			DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date reqdate2 = new Date();
			response_time = dateFormat2.format(reqdate2);
			Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + mapheader.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
			Log.aua.info("Response Meta Data Details::Staus Message:Invalid Request method" + "::" + "ResponseTime::" + response_time + "::Status Code:A105" + "::ResTranscation id:" + "");

			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

			JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A105").add("Message", "Invalid Request method.");
			JsonObject dataJsonObject = value2.build();
			model.addAttribute("model", dataJsonObject);
			return new ModelAndView("demographicauth");

		}

		return new ModelAndView("demographicauth");

	}

}
