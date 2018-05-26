package com.auth.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

import com.auth.bean.deviceDetails;
import com.auth.bean.normalAuthDetails;
import com.auth.bean.subAua;
import com.auth.dao.BioDAO;
import com.auth.dao.NormalDetailsDAO;
import com.auth.dao.SubAuaDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.service.BioService;
import com.auth.util.AUAUtilities;
import com.auth.util.IpassCustomBase64;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
import com.auth.util.Util;
import com.ecs.asa.processor.AuthProcessor;
import com.ecs.asa.processor.AuthProcessor.RcType;
import com.ecs.asa.processor.AuthProcessor.TidType;
import com.ecs.asa.utils.HttpConnector;
import com.ecs.exceptions.AsaServerException;
import com.ecs.exceptions.InvalidResponseException;
import com.ecs.exceptions.UidaiSignatureVerificationFailedException;
import com.ecs.exceptions.XMLParsingException;
import com.google.gson.JsonParser;
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;

@Controller
public class BioApiController {

	@Autowired
	private NormalDetailsDAO normaldetaildao;

	@Autowired
	private VerificationDAO verificationDAO;

	@Autowired
	private UserLoginDAO userLogindao;

	@Autowired
	private BioDAO bioDAO;

	@Autowired
	private BioService bioservice;

	@Autowired
	private SubAuaDAO subauadao;

	@RequestMapping(value = "/bioauth", method = { RequestMethod.POST, RequestMethod.GET })
	public ModelAndView bioauth(Model model, @RequestBody String authdata, HttpSession session, HttpServletRequest request, HttpServletResponse response) throws Exception {

		PREAUAProperties.load();

		Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
		Boolean enryptedFlag = true;
		Map<String, String> map = new HashMap<String, String>();
		Enumeration headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = request.getHeader(key);
			map.put(key, value);

		}
		// Global Variables
		String auth_data = "", aadharcardnumber = "", verifyby = "", token = "", udc = "";

		String request_time = "";
		DateFormat rdateFormatt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
		Date rreqdatee = new Date();
		request_time = rdateFormatt.format(rreqdatee);

		if (StringUtils.isEmpty(map.get("client_id"))) {
			enryptedFlag = false;
		}
		if (request.getMethod().toUpperCase().contains("POST")) {

			if (map.get("content-type").trim().equalsIgnoreCase("application/json")) {
				Properties properties = new Properties();
				/** Aadhaar errorcode checked **/
				ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
				properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

				String flocation = "", fpostalcode = "", fcity = "";
				String subAuaCode = "";
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

					// Get Bodydata Process
					if (enryptedFlag) {

						Log.aua.info("User Logged As ::" + map.get("client_id").trim());
						verifyby = map.get("client_id").trim();

						normalAuthDetails urldata = normaldetaildao.getOneById(verifyby);

						String rclientid = "", clientlimit = "";

						if (StringUtils.isNotEmpty(urldata.getClient_id())) {

							subAua subauaDetails = subauadao.getSubAUA(map.get("subauacode"));
							if (subauaDetails == null) {
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
								Log.aua.info("SubAUACODE:::" + map.get("subauacode") + "::Invalid SubAUA");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("biometricauth");
							} else {
								subAuaCode = subauaDetails.getSubaua_code().trim();
							}

							rclientid = urldata.getClient_id();
							token = urldata.getAut_token();

							auth_data = AUAUtilities.doDecrypt(token, authdata.trim());
							if (auth_data.contentEquals("A900")) {

								String response_time = "";
								DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
								Date rreqdatee1 = new Date();
								response_time = rdateFormatt1.format(rreqdatee1);

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:Invalid encryption" + "::" + "ResponseTime::" + response_time + "::Status Code:A114" + "::ResTranscation id:" + "");

								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A114").add("Message", "Invalid encryption.");
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("biometricauth");
							}

						} else {

							String response_time = "";
							DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date rreqdatee1 = new Date();
							response_time = rdateFormatt1.format(rreqdatee1);
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:You are not authorized to make such request. Please contact system administrator" + "::" + "ResponseTime::" + response_time + "::Status Code:A102" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A102").add("Message", "You are not authorized to make such request. Please contact system administrator.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("biometricauth");
						}

					} else {

						if (StringUtils.isNotEmpty(map.get("username")) && StringUtils.isNotEmpty(map.get("password"))) {

							boolean isDemoValidUser = subauadao.isValidClient(map.get("username"), map.get("password"));

							subAua subauaDetails = subauadao.getSubAUA(map.get("username"));

							if (isDemoValidUser == false) {
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
								Log.aua.info("User:::" + map.get("username") + "::Invalid user");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A102").add("Message", "You are not authorized to make such request. Please contact system administrator.");

								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("biometricauth");

							} else {

								if (subauaDetails == null) {
									response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
									Log.aua.info("SubAUA:::" + map.get("subauacode") + "::Invalid SubAUA");
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("biometricauth");
								} else {
									subAuaCode = subauaDetails.getSubaua_code().trim();
								}

							}
							auth_data = authdata.trim();
							verifyby = map.get("username").trim();
							Log.aua.info("User Logged As ::" + map.get("username").trim());
						} else {

							String response_time = "";
							DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date reqdate2 = new Date();
							response_time = dateFormat2.format(reqdate2);
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Bad request. Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad request. Please check your headers.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("biometricauth");
						}
					}
					// End process

					try {
						JsonParser parser = new JsonParser();
						parser.parse(auth_data);
						JSONObject jsonObj = new JSONObject(auth_data);
						if (StringUtils.isNotEmpty(jsonObj.getString("aadhaarnumber").toString()) && StringUtils.isNotEmpty(jsonObj.getString("data").toString())) {

							IpassCustomBase64 piddecodestring = new IpassCustomBase64();

							String pidwebapidata = piddecodestring.decode(jsonObj.getString("data").toString().trim());

							org.jsoup.nodes.Document doc2 = null;
							try {

								doc2 = Jsoup.parse(pidwebapidata, "", Parser.xmlParser());
								if (StringUtils.isEmpty(doc2.getElementsByTag("DeviceInfo").attr("dc").trim())) {
									response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
									String response_time = "";

									DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate2 = new Date();
									response_time = dateFormat2.format(reqdate2);

									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");

									Log.aua.info("Response Meta Data Details::Invalid pid xml" + "::" + "ResponseTime::" + response_time + "::Status Code:A115" + "::ResTranscation id:" + "");

									// Demo log

									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A115").add("Message", "Invalid pid xml.");
									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("biometricauth");

								}

							} catch (Exception e) {

								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
								String response_time = "";

								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");

								Log.aua.info("Response Meta Data Details::Invalid pid xml" + "::" + "ResponseTime::" + response_time + "::Status Code:A115" + "::ResTranscation id:" + "");

								// Demo log

								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A115").add("Message", "Invalid pid xml.");
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("biometricauth");
							}

							udc = doc2.getElementsByTag("DeviceInfo").attr("dc").trim();

							if (StringUtils.isNotEmpty(udc)) {

								int isValidDevice = bioDAO.isValidDevice(udc);
								if (isValidDevice != 1) {
									String mi = "", datecreated = "";

									mi = doc2.getElementsByTag("DeviceInfo").attr("mi").trim();
									DateFormat dateFormat3 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate3 = new Date();
									datecreated = dateFormat3.format(reqdate3);

									deviceDetails dedetails = new deviceDetails();

									dedetails.setUDC(udc);
									dedetails.setMCNAME(mi);
									dedetails.setSTATUS("1");
									dedetails.setSERIALNUMBER("NA");
									dedetails.setCREATEDON(datecreated);
									dedetails.setCLIENTID(verifyby);

									int deviceid = bioDAO.save(dedetails);
								}

								aadharcardnumber = jsonObj.getString("aadhaarnumber").toString().trim();

								Pattern p = Pattern.compile("^\\d{12}$");
								Matcher numberMatcher;
								numberMatcher = p.matcher(aadharcardnumber);

								if (numberMatcher.matches()) {

									properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

									String pidXML = pidwebapidata;

									String utransactionId = "AUTHBRIDGE-" + AUAUtilities.generateUniqueId();

									AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()));

									DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate = new Date();
									request_time = dateFormat.format(reqdate);

									try {
										pro.setUid(aadharcardnumber.trim());
										pro.setAc(PREAUAProperties.getUidai_aua_code());
										pro.setSa(subAuaCode);
										pro.setRc(RcType.Y);
										pro.setTid(TidType.registered);
										pro.setLk(PREAUAProperties.getUidai_license_key());
										pro.setTxn(utransactionId);
										pro.setRDRespone(pidXML, "FMR", false, false, false, false, false, "UDC0001");
										String requestXml = "";

										try {

											requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

											String responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);

											try {
												AuthRes authres = pro.parse(responseXml);

												if (authres.getRet() == AuthResult.Y) {

													response.setStatus(HttpServletResponse.SC_OK);
													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:A200" + "::ResTranscation id:" + authres.getTxn());

													bioservice.saveBio(authres, udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A200").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("Transactionid", authres.getTxn()).add("Message", "Authentication Success.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
													return new ModelAndView("biometricauth");

												} else {
													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + properties.getProperty(authres.getErr()) + "::" + "ResponseTime::" + response_time + "::Status Code:" + authres.getErr() + "::ResTranscation id:" + authres.getTxn());
													response.setStatus(HttpServletResponse.SC_OK);
													bioservice.saveBio(authres, udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A201").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("Transactionid", authres.getTxn()).add("Error", authres.getErr()).add("Message", properties.getProperty(authres.getErr()));

													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
													return new ModelAndView("biometricauth");
												}

											} catch (AsaServerException ex) {

												if (ex.getCode().trim().contentEquals("ASA002")) {

													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);

													response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
													org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ex.getCode() + "::ResTranscation id:" + "");
													bioservice.saveExceptionDemo(ex.getCode(), ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A113").add("Message", "AUA configuration not found. Please contact system administrator.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("biometricauth");

												} else {

													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);

													response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
													org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ex.getCode() + "::ResTranscation id:" + "");
													bioservice.saveExceptionDemo(ex.getCode(), ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A211").add("Error", ex.getCode()).add("Message", ex.getMessage());
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("biometricauth");

												}

											} catch (XMLParsingException ex) {

												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

												bioservice.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A212").add("Error", ((Element) doc).select("Code").text()).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("biometricauth");

											} catch (InvalidResponseException ex) {

												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

												bioservice.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A213").add("Error", ((Element) doc).select("Code").text()).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("biometricauth");

											} catch (UidaiSignatureVerificationFailedException ex) {

												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ((Element) doc).select("Code").text() + "::ResTranscation id:" + "");

												bioservice.saveExceptionDemo(((Element) doc).select("Code").text(), ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A214").add("Error", ((Element) doc).select("Code").text()).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();

												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("biometricauth");

											} catch (Exception ex) {

												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);

												if (ex.getMessage().contentEquals("Invalid uid")) {

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

													response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
													bioservice.saveExceptionDemo("998", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("biometricauth");

												} else {

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A216" + "::ResTranscation id:" + "");

													response.setStatus(HttpServletResponse.SC_NOT_FOUND);
													bioservice.saveExceptionDemo("A216", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A216").add("Message", "ASA server down. Please contact technical team.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("biometricauth");
												}
											}

										} catch (Exception ex) {

											String response_time = "";
											DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
											Date reqdate2 = new Date();
											response_time = dateFormat2.format(reqdate2);

											if (ex.getMessage().contentEquals("Invalid uid") || ex.getMessage().contentEquals("UID cannot be null or empty")) {

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);

												bioservice.saveExceptionDemo("998", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("biometricauth");

											} else {

												response.setStatus(HttpServletResponse.SC_NOT_FOUND);

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A216" + "::ResTranscation id:" + "");

												bioservice.saveExceptionDemo("A216", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A216").add("Message", "ASA server down. Please contact technical team");
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("biometricauth");
											}

										}

									} catch (NullPointerException ex) {

										ex.printStackTrace();

										String response_time = "";
										DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
										Date reqdate2 = new Date();
										response_time = dateFormat2.format(reqdate2);

										Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
										Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A115" + "::ResTranscation id:" + "");

										response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
										bioservice.saveExceptionDemo("A115", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

										JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A115").add("Message", "Invalid pid xml.");
										JsonObject dataJsonObject = value2.build();
										model.addAttribute("model", dataJsonObject);
										return new ModelAndView("biometricauth");
									}

									catch (Exception ex) {

										String response_time = "";
										DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
										Date reqdate2 = new Date();
										response_time = dateFormat2.format(reqdate2);

										if (ex.getMessage().contentEquals("Invalid uid")) {

											Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
											Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

											response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
											bioservice.saveExceptionDemo("998", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

											JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
											JsonObject dataJsonObject = value2.build();
											model.addAttribute("model", dataJsonObject);
											return new ModelAndView("biometricauth");

										} else {

											Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
											Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A216" + "::ResTranscation id:" + "");

											response.setStatus(HttpServletResponse.SC_NOT_FOUND);
											bioservice.saveExceptionDemo("A216", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

											JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A216").add("Message", "ASA server down. Please contact technical team.");
											JsonObject dataJsonObject = value2.build();
											model.addAttribute("model", dataJsonObject);
											return new ModelAndView("biometricauth");
										}
									}

								} else {

									String response_time = "";
									DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate2 = new Date();
									response_time = dateFormat2.format(reqdate2);
									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Aadhaar Number should be 12 digits numbers" + "::" + "ResponseTime::" + response_time + "::Status Code:A110" + "::ResTranscation id:" + "");

									response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A110").add("Message", "Aadhaar Number should be 12 digits numbers.");

									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("biometricauth");
								}

							}

						} else {

							String response_time = "";
							DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date rreqdatee1 = new Date();
							response_time = rdateFormatt1.format(rreqdatee1);

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Invalid Request! please check aadhaar number/or data" + "::" + "ResponseTime::" + response_time + "::Status Code:A107" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A107").add("Message", "Invalid Request. please check aadhaar number/or data");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("biometricauth");

						}

					} catch (JSONException e) {

						String response_time = "";
						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:Invalid Json" + "::" + "ResponseTime::" + response_time + "::Status Code:A106" + "::ResTranscation id:" + "");
						// Demo log

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A106").add("Message", "Invalid Json.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);
						return new ModelAndView("biometricauth");

					} catch (Exception ex) {

						String response_time = "";
						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);
						if (ex.getMessage().contains("Cannot open connection")) {

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:There is something technical issue! Please contact support team" + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							bioservice.saveExceptionDemo("A217", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);

						} else {

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Something went wrong. Please contact technical team." + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							bioservice.saveExceptionDemo("A217", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
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

					if (ex.getMessage().contains("Cannot open connection")) {

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:There is something technical issue! Please contact support team" + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						bioservice.saveExceptionDemo("A217", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);

					} else {
						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:There is something technical issue! Please contact support team" + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						bioservice.saveExceptionDemo("A217", ex.getMessage(), udc, aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
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

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Bad Request! Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad Request. Please check your headers.");
				JsonObject dataJsonObject = value2.build();
				model.addAttribute("model", dataJsonObject);

			}

		} else {

			String response_time = "";
			DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date reqdate2 = new Date();
			response_time = dateFormat2.format(reqdate2);
			Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + map.get("subauacode") + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
			Log.aua.info("Response Meta Data Details::Staus Message:Invalid Request method" + "::" + "ResponseTime::" + response_time + "::Status Code:A105" + "::ResTranscation id:" + "");

			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

			JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A105").add("Message", "Invalid Request method.");
			JsonObject dataJsonObject = value2.build();
			model.addAttribute("model", dataJsonObject);
			return new ModelAndView("biometricauth");

		}
		return new ModelAndView("biometricauth");

	}

}
