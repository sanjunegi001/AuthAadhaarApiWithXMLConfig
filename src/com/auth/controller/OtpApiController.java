package com.auth.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
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
import org.jsoup.parser.Parser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.auth.bean.normalAuthDetails;
import com.auth.bean.otpGeneration;
import com.auth.bean.subAua;
import com.auth.dao.NormalDetailsDAO;
import com.auth.dao.OtpGenDAO;
import com.auth.dao.SubAuaDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.service.OtpSerivce;
import com.auth.util.AUAUtilities;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
import com.auth.util.Util;
import com.ecs.asa.processor.AuthProcessor;
import com.ecs.asa.processor.AuthProcessor.RcType;
import com.ecs.asa.processor.AuthProcessor.TidType;
import com.ecs.asa.processor.OtpProcessor;
import com.ecs.asa.processor.OtpProcessor.ChannelType;
import com.ecs.asa.processor.OtpProcessor.MobileEmail;
import com.ecs.asa.processor.OtpProcessor.OtpType;
import com.ecs.asa.utils.HttpConnector;
import com.ecs.exceptions.AsaServerException;
import com.ecs.exceptions.InvalidResponseException;
import com.ecs.exceptions.UidaiSignatureVerificationFailedException;
import com.ecs.exceptions.XMLParsingException;
import com.google.gson.JsonParser;
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.otp_response._1.OtpRes;
import in.gov.uidai.authentication.otp_response._1.OtpResult;
import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;

@Controller
public class OtpApiController {

	@Autowired
	private UserLoginDAO userLogindao;

	@Autowired
	private OtpSerivce otpservice;

	@Autowired
	private OtpGenDAO otpgenDao;

	@Autowired
	private VerificationDAO verificationDAO;

	@Autowired
	private NormalDetailsDAO normaldetailsDAO;

	@Autowired
	private SubAuaDAO subauadao;

	@RequestMapping(value = "/otpauth", method = { RequestMethod.POST, RequestMethod.GET })
	public ModelAndView otpauth(@RequestBody String authdata, HttpServletResponse response, HttpServletRequest request, HttpSession session, Model model) throws Exception {

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
		String auth_data = "", aadharcardnumber = "", verifyby = "", token = "", subAuaCode = "";

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
					Log.aua.info("CONSENT : CONSENT TAKEN BY USER!");
					Log.aua.info("Error Message::" + e1);
					e1.printStackTrace();

				}

				try {

					// Get Bodydata Process
					if (enryptedFlag) {

						Log.aua.info("User Logged As ::" + map.get("client_id").trim());
						verifyby = map.get("client_id").trim();

						normalAuthDetails urldata = normaldetailsDAO.getOneById(verifyby);

						String rclientid = "", clientlimit = "";

						if (StringUtils.isNotEmpty(urldata.getClient_id())) {

							subAua subauaDetails = subauadao.getSubAUA(map.get("subauacode"));

							if (subauaDetails == null) {
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
								Log.aua.info("SubAUACODE:::" + map.get("subauacode") + "::Invalid SubAUA");
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("otpauthapi");
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

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:Invalid encryption" + "::" + "ResponseTime::" + response_time + "::Status Code:A114" + "::ResTranscation id:" + "");

								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A114").add("Message", "Invalid encryption.");
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("otpauthapi");
							}

						} else {

							String response_time = "";
							DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date rreqdatee1 = new Date();
							response_time = rdateFormatt1.format(rreqdatee1);
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:You are not authorized to make such request. Please contact system administrator" + "::" + "ResponseTime::" + response_time + "::Status Code:A102" + "::ResTranscation id:" + "");
							response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A102").add("Message", "You are not authorized to make such request. Please contact system administrator.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("otpauthapi");
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
								return new ModelAndView("otpauthapi");

							} else {
								if (subauaDetails == null) {
									response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
									Log.aua.info("SubAUA:::" + map.get("subauacode") + "::Invalid SubAUA");
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A112").add("Message", "SUBAUA configuration not found. Please contact system administrator.");

									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("otpauthapi");
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
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Bad request. Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad request. Please check your headers.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("otpauthapi");
						}

					}

					try {

						JsonParser parser = new JsonParser();
						parser.parse(auth_data);

						JSONObject jsonObj = new JSONObject(auth_data);

						if (StringUtils.isNotEmpty(jsonObj.getString("authtype"))) {

							if (StringUtils.isNotEmpty(jsonObj.getString("uniqueid"))) {

								if (jsonObj.getString("authtype").trim().contentEquals("1")) {

									/**
									 * OTP
									 * GENERATION
									 **/

									aadharcardnumber = jsonObj.getString("aadhaarnumber").trim();

									Pattern p = Pattern.compile("^\\d{12}$");
									Matcher numberMatcher;
									numberMatcher = p.matcher(aadharcardnumber);

									if (numberMatcher.matches()) {

										if ((jsonObj.getString("channel").contentEquals("1")) || (jsonObj.getString("channel").contentEquals("2") || (jsonObj.getString("channel").contentEquals("3")))) {

											String uniqueid = "";
											uniqueid = jsonObj.getString("uniqueid").trim().replaceAll("\\s", "");
											if (uniqueid.length() > 9 && uniqueid.length() < 31) {

												List<otpGeneration> unique_id = otpgenDao.getDuplicate_ID(verifyby, uniqueid);
												if (unique_id.size() > 0) {

													String response_time = "";
													DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate2 = new Date();
													response_time = dateFormat2.format(reqdate2);
													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:Duplicate unique id" + "::" + "ResponseTime::" + response_time + "::Status Code:A111" + "::ResTranscation id:" + "");
													response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A111").add("Message", "Duplicate unique id.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);

												} else {

													String utransactionId = "";
													utransactionId = uniqueid.trim();

													OtpProcessor opro = new OtpProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()));

													opro.setUid(aadharcardnumber);
													opro.setTxn(utransactionId);
													opro.setAc(PREAUAProperties.getUidai_aua_code());
													opro.setSa(subAuaCode);
													opro.setLk(PREAUAProperties.getUidai_license_key());
													opro.setTid(com.ecs.asa.processor.OtpProcessor.TidType.PUBLIC);
													opro.setType(OtpType.AADHAAR_NUMBER);
													if (jsonObj.getString("channel").trim().contentEquals("1"))
														opro.setCh(ChannelType.SMS_ONLY);
													else if (jsonObj.getString("channel").trim().contentEquals("2"))
														opro.setCh(ChannelType.EMAIL_ONLY);
													else
														opro.setCh(ChannelType.SMS_AND_EMAIL);

													String oRequestXml = "";
													String oResponseXml = "";

													try {

														oRequestXml = opro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

														oResponseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), oRequestXml);

														OtpRes ores = opro.parse(oResponseXml);
														if (ores.getRet() == OtpResult.Y) {

															String response_time = "";
															DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate1 = new Date();
															response_time = dateFormat1.format(reqdate1);
															response.setStatus(HttpServletResponse.SC_OK);

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:OTP Genration Successfull" + "::" + "ResponseTime::" + response_time + "::Status Code:A200" + "::ResTranscation id:" + ores.getTxn());

															MobileEmail me = opro.getMaskedMobileEmail(ores);
															if (StringUtils.isEmpty(me.getEmail()) && StringUtils.isNotEmpty(me.getMobileNumber())) {

																otpservice.saveOtpGen(ores, String.format("OTP sent to Mobile Number %s", me.getMobileNumber()), aadharcardnumber, utransactionId, request_time, response_time, subAuaCode, verifyby);

																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A200").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("TransactionID", utransactionId).add("Message", String.format("OTP sent to Mobile Number %s", me.getMobileNumber()));

																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
																return new ModelAndView("otpauthapi");
															} else if (StringUtils.isNotEmpty(me.getEmail()) && StringUtils.isEmpty(me.getMobileNumber())) {

																otpservice.saveOtpGen(ores, String.format("OTP sent to Email Id %s", me.getEmail()), aadharcardnumber, utransactionId, request_time, response_time, subAuaCode, verifyby);

																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A200").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("TransactionID", utransactionId).add("Message", String.format("OTP sent to Email Id %s", me.getEmail()));
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
																return new ModelAndView("otpauthapi");
															} else {

																otpservice.saveOtpGen(ores, String.format("OTP sent to Mobile Number %s Email Id %s", me.getMobileNumber(), me.getEmail()), aadharcardnumber, utransactionId, request_time, response_time, subAuaCode, verifyby);

																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A200").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("TransactionID", utransactionId).add("Message", String.format("OTP sent to Mobile Number %s Email Id %s", me.getMobileNumber(), me.getEmail()));
																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
																return new ModelAndView("otpauthapi");
															}

														} else {

															String response_time = "";
															DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate1 = new Date();
															response_time = dateFormat1.format(reqdate1);
															response.setStatus(HttpServletResponse.SC_OK);

															if (ores.getErr().contentEquals("952")) {
																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:OTP Flooding - Please avoid trying to generate the OTP multiple times within short time" + "::" + "ResponseTime::" + response_time + "::Status Code:952" + "::ResTranscation id:" + ores.getTxn());
																otpservice.saveOtpGen(ores, "OTP Flooding - Please avoid trying to generate the OTP multiple times within short time", aadharcardnumber, utransactionId, request_time, response_time, subAuaCode, verifyby);

																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A201").add("Error", "952").add("Uid", Util.maskCardNumber(aadharcardnumber)).add("TransactionID", utransactionId).add("Message", "OTP Flooding. Please avoid trying to generate the OTP multiple times within short time.");

																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());

															} else {

																Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
																Log.aua.info("Response Meta Data Details::Staus Message:" + properties.getProperty(ores.getErr()) + "::" + "ResponseTime::" + response_time + "::Status Code:" + ores.getErr() + "::ResTranscation id:" + ores.getTxn());
																otpservice.saveOtpGen(ores, ores.getErr(), aadharcardnumber, utransactionId, request_time, response_time, subAuaCode, verifyby);
																JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A201").add("Error", ores.getErr()).add("Uid", Util.maskCardNumber(aadharcardnumber)).add("TransactionID", utransactionId).add("Message", properties.getProperty(ores.getErr()));

																JsonObject dataJsonObject = value2.build();
																model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
															}

															return new ModelAndView("otpauthapi");

														}
													} catch (XMLParsingException ex) {

														response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
														String response_time = "";
														DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
														Date reqdate1 = new Date();
														response_time = dateFormat1.format(reqdate1);
														org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + oResponseXml, "", Parser.xmlParser());

														Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
														Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

														otpservice.saveExceptionGenOtp(doc.select("Code").text(), ex.getMessage(), aadharcardnumber, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
														JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A212").add("Error", doc.select("Code").text()).add("Message", ex.getMessage());
														JsonObject dataJsonObject = value2.build();
														model.addAttribute("model", dataJsonObject);

													} catch (InvalidResponseException ex) {
														response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
														String response_time = "";
														DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
														Date reqdate1 = new Date();
														response_time = dateFormat1.format(reqdate1);
														org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + oResponseXml, "", Parser.xmlParser());

														Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
														Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

														otpservice.saveExceptionGenOtp(doc.select("Code").text(), ex.getMessage(), aadharcardnumber, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
														JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A213").add("Error", doc.select("Code").text()).add("Message", ex.getMessage());
														JsonObject dataJsonObject = value2.build();
														model.addAttribute("model", dataJsonObject);

													} catch (AsaServerException ex) {

														if (ex.getCode().contentEquals("ASA002")) {
															String response_time = "";
															DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate2 = new Date();
															response_time = dateFormat2.format(reqdate2);
															otpservice.saveExceptionGenOtp(ex.getCode(), ex.getMessage(), aadharcardnumber, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
															response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
															Log.aua.info("User:::" + map.get("subauacode") + "::Invalid SubAUA");
															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A113").add("Message", "AUA configuration not found. Please contact system administrator.");

															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);
														}

														else {
															response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
															String response_time = "";
															DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
															Date reqdate1 = new Date();
															response_time = dateFormat1.format(reqdate1);
															org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + oResponseXml, "", Parser.xmlParser());

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

															otpservice.saveExceptionGenOtp(ex.getCode(), ex.getMessage(), aadharcardnumber, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A211").add("Error", doc.select("Code").text()).add("Message", ex.getMessage());
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);
														}

													} catch (UidaiSignatureVerificationFailedException ex) {

														response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
														String response_time = "";
														DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
														Date reqdate1 = new Date();
														response_time = dateFormat1.format(reqdate1);
														org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + oResponseXml, "", Parser.xmlParser());

														Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
														Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

														otpservice.saveExceptionGenOtp(doc.select("Code").text(), ex.getMessage(), aadharcardnumber, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
														JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A214").add("Error", doc.select("Code").text()).add("Message", ex.getMessage());
														JsonObject dataJsonObject = value2.build();
														model.addAttribute("model", dataJsonObject);

													}

													catch (Exception e) {

														String response_time = "";
														DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
														Date reqdate2 = new Date();
														response_time = dateFormat2.format(reqdate2);

														if (e.getMessage().contentEquals("Invalid uid")) {

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

															response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
															otpservice.saveExceptionGenOtp("998", e.getMessage(), aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														} else {

															Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
															Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A211" + "::ResTranscation id:" + "");

															response.setStatus(HttpServletResponse.SC_NOT_FOUND);
															otpservice.saveExceptionGenOtp("A216", e.getMessage(), aadharcardnumber.trim(), request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

															JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A216").add("Message", "ASA server down.Please contact technical team.");
															JsonObject dataJsonObject = value2.build();
															model.addAttribute("model", dataJsonObject);

														}
														return new ModelAndView("otpauthapi");

													}
												}

											} else {
												String response_time = "";
												DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate1 = new Date();
												response_time = dateFormat1.format(reqdate1);

												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:Uniqueid  is not valid" + "::" + "ResponseTime::" + response_time + "::Status Code:A126" + "::ResTranscation id:" + "");
												response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A126").add("Message", "Uniqueid  is not valid.");

												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject);
												return new ModelAndView("otpauthapi");

											}

										} else {

											String response_time = "";
											DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
											Date reqdate2 = new Date();
											response_time = dateFormat2.format(reqdate2);

											Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
											Log.aua.info("Response Meta Data Details::Staus Message:Channel value not allowed" + "::" + "ResponseTime::" + response_time + "::Status Code:A117" + "::ResTranscation id:" + "");

											response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
											JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A117").add("Message", "Channel value not allowed.");
											JsonObject dataJsonObject = value2.build();
											model.addAttribute("model", dataJsonObject);
											return new ModelAndView("otpauthapi");

										}

									} else {

										String response_time = "";
										DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
										Date reqdate1 = new Date();
										response_time = dateFormat1.format(reqdate1);

										Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
										Log.aua.info("Response Meta Data Details::Staus Message:Channel value not allowed" + "::" + "ResponseTime::" + response_time + "::Status Code:A110" + "::ResTranscation id:" + "");

										response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
										JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A110").add("Message", "Aadhaar Number should be 12 digits.");

										JsonObject dataJsonObject = value2.build();
										model.addAttribute("model", dataJsonObject);
										return new ModelAndView("otpauthapi");

									}

								} else if (jsonObj.getString("authtype").trim().contentEquals("2")) {

									if (StringUtils.isNotEmpty(jsonObj.getString("otp"))) {

										List<otpGeneration> aadhaar = otpgenDao.getaadhaarNumber(jsonObj.getString("uniqueid"), verifyby);

										if (aadhaar.size() < 1) {

											DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
											Date reqdate = new Date();
											request_time = dateFormat.format(reqdate);

											String response_time = "";
											DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
											Date reqdate1 = new Date();
											response_time = dateFormat1.format(reqdate1);

											Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
											Log.aua.info("Response Meta Data Details::Staus Message:Unique id is not valid" + "::" + "ResponseTime::" + response_time + "::Status Code:A111" + "::ResTranscation id:" + "");

											response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
											JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A111").add("Message", "Duplicate unique id.");
											JsonObject dataJsonObject = value2.build();
											model.addAttribute("model", dataJsonObject);
											return new ModelAndView("otpauthapi");

										} else {

											String otp = "";
											String uniqueid = "";
											String uid = "";
											String trid = "";

											otp = jsonObj.getString("otp");
											uniqueid = jsonObj.getString("uniqueid");

											uid = Long.toString(aadhaar.get(0).getUID());
											trid = aadhaar.get(0).getTRANSACTION_ID();
											uniqueid = aadhaar.get(0).getUNIQUE_ID();

											AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()), PREAUAProperties.readAll(PREAUAProperties.getUidai_signing_cert()));
											pro.setUid(uid);
											pro.setAc(PREAUAProperties.getUidai_aua_code());
											pro.setSa(subAuaCode);
											pro.setRc(RcType.Y);
											pro.setTid(TidType.None);
											pro.setLk(PREAUAProperties.getUidai_license_key());
											pro.setTxn(trid);
											pro.prepareOtpPIDBlock(otp, "AUT122333");
											String requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

											String responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);

											int otpt = otpgenDao.updateOtpgen(verifyby, jsonObj.getString("uniqueid").trim());

											try {

												String response_time = "";
												DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate1 = new Date();
												response_time = dateFormat1.format(reqdate1);

												AuthRes res = pro.parse(responseXml);
												if (res.getRet() == AuthResult.Y) {

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:A200" + "::ResTranscation id:" + res.getTxn());

													otpservice.saveOtpVer(res, uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
													response.setStatus(HttpServletResponse.SC_OK);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A200").add("Uid", Util.maskCardNumber(uid)).add("TransactionID", uniqueid).add("Message", "Authentication Success.");

													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
													return new ModelAndView("otpauthapi");
												} else {

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + properties.getProperty(res.getErr()) + "::" + "ResponseTime::" + response_time + "::Status Code:" + res.getErr() + "::ResTranscation id:" + res.getTxn());
													otpservice.saveOtpVer(res, uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
													response.setStatus(HttpServletResponse.SC_OK);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A201").add("Error", res.getErr()).add("Uid", Util.maskCardNumber(uid)).add("TransactionID", uniqueid).add("Message", properties.getProperty(res.getErr()));
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", (enryptedFlag) ? AUAUtilities.doEncrypt(token, dataJsonObject.toString()) : dataJsonObject.toString().trim());
													return new ModelAndView("otpauthapi");
												}
											} catch (XMLParsingException ex) {

												String response_time = "";
												DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate1 = new Date();
												response_time = dateFormat1.format(reqdate1);

												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

												otpservice.saveExceptionOtp(doc.select("Code").text(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A212").add("Error", doc.select("Code").text()).add("TransactionID", uniqueid).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject.toString().trim());
												return new ModelAndView("otpauthapi");
											} catch (AsaServerException ex) {

												if (ex.getCode().contentEquals("ASA002")) {

													String response_time = "";
													DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate1 = new Date();
													response_time = dateFormat1.format(reqdate1);

													org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

													otpservice.saveExceptionOtp(ex.getCode(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A113").add("Message", "AUA configuration not found. Please contact system administrator.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject.toString().trim());
													return new ModelAndView("otpauthapi");

												} else {
													String response_time = "";
													DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
													Date reqdate1 = new Date();
													response_time = dateFormat1.format(reqdate1);

													org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

													otpservice.saveExceptionOtp(doc.select("Code").text(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A211").add("Error", doc.select("Code").text()).add("TransactionID", uniqueid).add("Message", ex.getMessage());
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject.toString().trim());
													return new ModelAndView("otpauthapi");
												}

											} catch (InvalidResponseException ex) {

												String response_time = "";
												DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate1 = new Date();
												response_time = dateFormat1.format(reqdate1);

												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

												otpservice.saveExceptionOtp(doc.select("Code").text(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A213").add("Error", doc.select("Code").text()).add("TransactionID", uniqueid).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject.toString().trim());
												return new ModelAndView("otpauthapi");

											} catch (UidaiSignatureVerificationFailedException ex) {

												String response_time = "";
												DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate1 = new Date();
												response_time = dateFormat1.format(reqdate1);

												org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
												Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
												Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

												otpservice.saveExceptionOtp(doc.select("Code").text(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A214").add("Error", doc.select("Code").text()).add("TransactionID", uniqueid).add("Message", ex.getMessage());
												JsonObject dataJsonObject = value2.build();
												model.addAttribute("model", dataJsonObject.toString().trim());
												return new ModelAndView("otpauthapi");

											} catch (Exception ex) {

												String response_time = "";
												DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
												Date reqdate2 = new Date();
												response_time = dateFormat2.format(reqdate2);
												response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
												if (ex.getMessage().contentEquals("Invalid uid")) {

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

													otpservice.saveExceptionOtp("998", ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A215").add("Error", "998").add("Message", "Invalid Aadhaar Number.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
													return new ModelAndView("otpauthapi");
												} else {

													org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

													Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
													Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A216" + "::ResTranscation id:" + "");

													otpservice.saveExceptionOtp(doc.select("Code").text(), ex.getMessage(), uid, request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

													JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A216").add("Message", "ASA server down. Please contact technical team.");
													JsonObject dataJsonObject = value2.build();
													model.addAttribute("model", dataJsonObject);
												}

											}

										}

									} else {
										String response_time = "";
										DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
										Date reqdate2 = new Date();
										response_time = dateFormat2.format(reqdate2);

										Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
										Log.aua.info("Response Meta Data Details::Staus Message:Otp is required" + "::" + "ResponseTime::" + response_time + "::Status Code:A118" + "::ResTranscation id:" + "");
										response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
										JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A118").add("Message", "Otp is required.");
										JsonObject dataJsonObject = value2.build();
										model.addAttribute("model", dataJsonObject);
										return new ModelAndView("otpauthapi");

									}

								} else {
									String response_time = "";
									DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
									Date reqdate2 = new Date();
									response_time = dateFormat2.format(reqdate2);
									Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
									Log.aua.info("Response Meta Data Details::Staus Message:Invalid authtype" + "::" + "ResponseTime::" + response_time + "::Status Code:A119" + "::ResTranscation id:" + "");
									// otpservice.errorOtpGen(verifyby, "Invalid authtype", "A112", request_time, response_time);
									response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
									JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A119").add("Message", "Invalid authtype.");
									JsonObject dataJsonObject = value2.build();
									model.addAttribute("model", dataJsonObject);
									return new ModelAndView("otpauthapi");

								}

							} else {

								String response_time = "";
								DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
								Date reqdate2 = new Date();
								response_time = dateFormat2.format(reqdate2);

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:Uniqueid  is required" + "::" + "ResponseTime::" + response_time + "::Status Code:A116" + "::ResTranscation id:" + "");

								// otpservice.errorOtpGen(verifyby, "Uniqueid is required", "A111", request_time, response_time);
								response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
								JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A116").add("Message", "Uniqueid  is required.");
								JsonObject dataJsonObject = value2.build();
								model.addAttribute("model", dataJsonObject);
								return new ModelAndView("otpauthapi");
							}

						} else {

							String response_time = "";
							DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
							Date reqdate2 = new Date();
							response_time = dateFormat2.format(reqdate2);

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Authentication type  is required" + "::" + "ResponseTime::" + response_time + "::Status Code:A113" + "::ResTranscation id:" + "");

							// otpservice.errorOtpGen(verifyby, "Authentication type is required", "A113", request_time, response_time);
							response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A123").add("Message", "Authentication type  is required.");

							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
							return new ModelAndView("otpauthapi");
						}

					} catch (JSONException e) {

						String response_time = "";
						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);
						otpservice.saveExceptionOtp("A209", e.getMessage(), "0", request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:Invalid Json" + "::" + "ResponseTime::" + response_time + "::Status Code:A106" + "::ResTranscation id:" + "");
						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A106").add("Message", "Invalid Json.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);
						return new ModelAndView("biometricauth");

					} catch (Exception e) {

						String response_time = "";
						DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
						Date reqdate2 = new Date();
						response_time = dateFormat2.format(reqdate2);
						response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
						otpservice.saveExceptionOtp("A217", e.getMessage(), "0", request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);

						if (e.getMessage().contains("Cannot open connection")) {
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);

						} else {
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");
							JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
							JsonObject dataJsonObject = value2.build();
							model.addAttribute("model", dataJsonObject);
						}
						return new ModelAndView("otpauthapi");
					}

				} catch (Exception e) {

					String response_time = "";
					DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
					Date reqdate2 = new Date();
					response_time = dateFormat2.format(reqdate2);
					response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
					otpservice.saveExceptionOtp("A217", e.getMessage(), "0", request_time, response_time, flocation, orgip, fcity, fpostalcode, subAuaCode, verifyby);
					if (e.getMessage().contains("Cannot open connection")) {

						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");

						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);

					} else {
						Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
						Log.aua.info("Response Meta Data Details::Staus Message:" + e.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:A209" + "::ResTranscation id:" + "");
						JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A217").add("Message", "Something went wrong. Please contact technical team.");
						JsonObject dataJsonObject = value2.build();
						model.addAttribute("model", dataJsonObject);

					}
					return new ModelAndView("otpauthapi");
				}

			} else {

				String response_time = "";
				DateFormat rdateFormatt1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date rreqdatee1 = new Date();
				response_time = rdateFormatt1.format(rreqdatee1);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Bad Request! Please check your headers." + "::" + "ResponseTime::" + response_time + "::Status Code:A100" + "::ResTranscation id:" + "");

				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A100").add("Message", "Bad Request. Please check your headers.");
				JsonObject dataJsonObject = value2.build();
				model.addAttribute("model", dataJsonObject);

				return new ModelAndView("otpauthapi");

			}
		} else {

			String response_time = "";
			DateFormat dateFormat2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date reqdate2 = new Date();
			response_time = dateFormat2.format(reqdate2);
			Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + subAuaCode + "::" + "ReqTransactionId::" + "" + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
			Log.aua.info("Response Meta Data Details::Staus Message:Invalid Request method" + "::" + "ResponseTime::" + response_time + "::Status Code:A105" + "::ResTranscation id:" + "");

			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

			JsonObjectBuilder value2 = Json.createObjectBuilder().add("StatusCode", "A105").add("Message", "Invalid Request method.");
			JsonObject dataJsonObject = value2.build();
			model.addAttribute("model", dataJsonObject);
			return new ModelAndView("otpauthapi");

		}

		return new ModelAndView("otpauthapi");
	}

}
