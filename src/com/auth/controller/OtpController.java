package com.auth.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.json.simple.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.auth.bean.Verification;
import com.auth.bean.otpGeneration;
import com.auth.dao.OtpGenDAO;
import com.auth.dao.UserLoginDAO;
import com.auth.dao.VerificationDAO;
import com.auth.domain.User;
import com.auth.util.AUAUtilities;
import com.auth.util.Log;
import com.auth.util.PREAUAProperties;
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
import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import in.gov.uidai.authentication.otp_response._1.OtpRes;
import in.gov.uidai.authentication.otp_response._1.OtpResult;
import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthResult;

@Controller
public class OtpController {

	/** The user login DAO. */
	@Autowired
	private UserLoginDAO userLogindao;

	@Autowired
	private OtpGenDAO otpgenDao;

	@Autowired
	private VerificationDAO verificationDAO;

	/**
	 * Biogenerate unique id.
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

	/** The otptransactionid. */
	String asaResponseXML = null, error_code = null, error_description = null, fingerpostion = null, biotransactionid = null;

	/**
	 * OTP Auth Home Page.
	 *
	 * @param model
	 *            the model
	 * @param session
	 *            the session
	 * @return the model and view
	 * @throws Exception
	 *             the exception
	 */

	@RequestMapping(value = "/otp", method = RequestMethod.GET)
	public ModelAndView Bio(Model model, HttpSession session) throws Exception {

		String propFilePath = "";

		try {
			PREAUAProperties.load();
			int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
			Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));
			if (session.getAttribute("user_login_name") != null && access == 1) {
				Log.aua.info("User Login ::" + session.getAttribute("user_login_name"));

				return new ModelAndView("OtpAuth");
			} else {
				Log.aua.info("User Login Failed::" + session.getAttribute("user_login_name"));
				return new ModelAndView("redirect:/login.html");

			}
		} catch (Exception e) {
			System.out.println(e);
			return new ModelAndView("redirect:/login.html");
		}

	}

	/**
	 * Otp generation.
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

	@RequestMapping(value = "/OtpGeneration", method = { RequestMethod.GET, RequestMethod.POST })
	public @ResponseBody String OtpGeneration(@ModelAttribute("user") User user, Model model, HttpServletRequest request, HttpSession session, @RequestParam(defaultValue = "false") boolean chkSms, @RequestParam(defaultValue = "false") boolean chkMail) throws Exception {

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
		String propFilePath = "";
		PREAUAProperties.load();

		if (session.getAttribute("user_login_name") != null && access == 1) {
			Log.aua.info("CONSENT: CONSENT TAKEN BY USER");
			Log.aua.info("User Login For OTP Auth :" + session.getAttribute("user_login_name"));

			DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date dateobj = new Date();
			String otpUtransactionId = "AUTHBRIDGE" + df.format(dateobj) + "-" + biogenerateUniqueId();

			request.getSession().setAttribute("otpaadhaarnumber", user.getAadharnumber());
			session.setAttribute("otpaadhaarnumber", user.getAadharnumber());

			OtpProcessor otpro = new OtpProcessor(PREAUAProperties.readAll(PREAUAProperties.uidai_encrypt_cert));

			otpro.setUid(user.getAadharnumber());
			otpro.setAc(PREAUAProperties.getUidai_aua_code());
			otpro.setSa(PREAUAProperties.getUidai_subaua_code());
			otpro.setTid(com.ecs.asa.processor.OtpProcessor.TidType.PUBLIC);
			otpro.setLk(PREAUAProperties.getUidai_license_key());
			otpro.setTxn(otpUtransactionId);
			otpro.setType(OtpType.AADHAAR_NUMBER);
			if (chkSms && !chkMail)
				otpro.setCh(ChannelType.SMS_ONLY);
			else if (chkMail && !chkSms)
				otpro.setCh(ChannelType.EMAIL_ONLY);
			else
				otpro.setCh(ChannelType.SMS_AND_EMAIL);

			/**
			 * Prepare AuthXML For Demo Auth For Sending Request To Asa
			 * 
			 */
			String requestotpxml = "";
			String responseotpxml = "";
			String request_time = "";
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date reqdate = new Date();
			request_time = dateFormat.format(reqdate);
			session.setAttribute("request_time", request_time);
			try {

				requestotpxml = otpro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

			} catch (Exception ex) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");

				if (ex.getMessage().contentEquals("Invalid uid")) {

					ex.getStackTrace();

					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE("Invalid Aadhaar Number");
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(0);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE("998");
					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");

					int ii = otpgenDao.save(ogen);
					JSONObject outputresults = new JSONObject();
					outputresults.put("message", "Invalid Aadhaar Number");
					outputresults.put("error", "998");
					outputresults.put("status", "0");
					return outputresults.toString();

				} else {

					ex.getStackTrace();
					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE("ASA server down!Please contact technical team");
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(0);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE("A108");
					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");

					int ii = otpgenDao.save(ogen);
					JSONObject outputresults = new JSONObject();
					outputresults.put("message", "ASA server down!Please contact technical team");
					outputresults.put("error", "A108");
					outputresults.put("status", "0");
					return outputresults.toString();
				}
			}

			try {

				responseotpxml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestotpxml);

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				JSONObject outputresults = new JSONObject();
				if (responseotpxml.startsWith("<Error>")) {

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Invalid OTP Generation Request" + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");
					outputresults.put("message", "Invalid OTP Generation Request");
					outputresults.put("status", "2");
					return outputresults.toString();
				}

				try {

					OtpRes ores = otpro.parse(responseotpxml);
					session.setAttribute("otptranscactionid", ores.getTxn());
					if (ores.getRet() == OtpResult.Y) {

						if (ores.getInfo() != null) {

							MobileEmail me = otpro.getMaskedMobileEmail(ores);

							if (me.getEmail() == null && me.getMobileNumber() != null) {

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + String.format("OTP sent to Mobile Number %s", me.getMobileNumber()) + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + "");
								otpGeneration ogen = null;
								ogen = new otpGeneration();
								ogen.setUID(Long.parseLong(user.getAadharnumber()));
								ogen.setTRANSACTION_ID(ores.getTxn());
								ogen.setUNIQUE_ID(otpUtransactionId);
								ogen.setSTATUS("1");
								ogen.setMESSAGE(String.format("OTP sent to Mobile Number %s", me.getMobileNumber()));
								ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
								ogen.setOTP_STATUS(1);
								ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
								ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
								ogen.setERRORCODE("");
								ogen.setSUB_AUA_CODE("STGABRPL01");
								ogen.setAUA_CODE("STGABRPL01");
								ogen.setENV_TYPE("PREPROD");
								ogen.setASA_NAME("CDSL");

								int ii = otpgenDao.save(ogen);

								outputresults.put("message", String.format("OTP Generation Successfull!!OTP sent to Mobile Number %s", me.getMobileNumber()));
								outputresults.put("status", "1");
								return outputresults.toString();

							} else if (me.getEmail() != null && me.getMobileNumber().contentEquals("NA")) {

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + String.format("OTP sent to Email id %s", me.getEmail()) + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + "");
								otpGeneration ogen = null;
								ogen = new otpGeneration();
								ogen.setUID(Long.parseLong(user.getAadharnumber()));
								ogen.setTRANSACTION_ID(ores.getTxn());
								ogen.setUNIQUE_ID(otpUtransactionId);
								ogen.setSTATUS("1");
								ogen.setMESSAGE(String.format("OTP sent to Email id %s", me.getEmail()));
								ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
								ogen.setOTP_STATUS(1);
								ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
								ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
								ogen.setERRORCODE("");
								ogen.setSUB_AUA_CODE("STGABRPL01");
								ogen.setAUA_CODE("STGABRPL01");
								ogen.setENV_TYPE("PREPROD");
								ogen.setASA_NAME("CDSL");

								int ii = otpgenDao.save(ogen);

								outputresults.put("message", String.format("OTP Generation Successfull!!OTP sent to Email id %s", me.getEmail()));
								outputresults.put("status", "1");
								return outputresults.toString();

							} else {

								Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
								Log.aua.info("Response Meta Data Details::Staus Message:" + String.format("OTP sent to Mobile Number %s Email Id %s", me.getMobileNumber(), me.getEmail()) + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + "");
								otpGeneration ogen = null;
								ogen = new otpGeneration();
								ogen.setUID(Long.parseLong(user.getAadharnumber()));
								ogen.setTRANSACTION_ID(ores.getTxn());
								ogen.setUNIQUE_ID(otpUtransactionId);
								ogen.setSTATUS("1");
								ogen.setMESSAGE(String.format("OTP sent to Mobile Number %s Email Id %s", me.getMobileNumber(), me.getEmail()));
								ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
								ogen.setOTP_STATUS(1);
								ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
								ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
								ogen.setERRORCODE("");
								ogen.setSUB_AUA_CODE("STGABRPL01");
								ogen.setAUA_CODE("STGABRPL01");

								ogen.setENV_TYPE("PREPROD");
								ogen.setASA_NAME("CDSL");
								int ii = otpgenDao.save(ogen);

								outputresults.put("message", String.format("OTP Generation Successfull!!OTP sent to Mobile Number %s Email Id %s", me.getMobileNumber(), me.getEmail()));
								outputresults.put("status", "1");
								return outputresults.toString();

							}

						} else {

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:Invalid OTP Generation Request" + "::" + "ResponseTime::" + response_time + "::Status Code:" + ores.getErr() + "::ResTranscation id:" + "");
							otpGeneration ogen = null;
							ogen = new otpGeneration();
							ogen.setUID(Long.parseLong(user.getAadharnumber()));
							ogen.setTRANSACTION_ID(ores.getTxn());
							ogen.setUNIQUE_ID(otpUtransactionId);
							ogen.setSTATUS("0");
							ogen.setMESSAGE(ores.getErr());
							ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
							ogen.setOTP_STATUS(0);
							ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
							ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
							ogen.setERRORCODE(ores.getCode());
							ogen.setSUB_AUA_CODE("STGABRPL01");
							ogen.setAUA_CODE("STGABRPL01");
							ogen.setENV_TYPE("PREPROD");
							ogen.setASA_NAME("CDSL");

							int ii = otpgenDao.save(ogen);
							outputresults.put("message", "Invalid OTP Generation Request");
							outputresults.put("error", ores.getErr());
							outputresults.put("status", "0");
							return outputresults.toString();
						}

					} else {

						if (ores.getErr().contentEquals("952")) {

							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:OTP Flooding - Please avoid trying to generate the OTP multiple times within short time" + "::" + "ResponseTime::" + response_time + "::Status Code:998" + "::ResTranscation id:" + "");
							otpGeneration ogen = null;
							ogen = new otpGeneration();
							ogen.setUID(Long.parseLong(user.getAadharnumber()));
							ogen.setTRANSACTION_ID(ores.getTxn());
							ogen.setUNIQUE_ID(otpUtransactionId);
							ogen.setSTATUS("0");
							ogen.setOTP_STATUS(2);
							ogen.setMESSAGE("OTP Flooding - Please avoid trying to generate the OTP multiple times within short time");
							ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
							ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
							ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
							ogen.setERRORCODE("A111");
							ogen.setSUB_AUA_CODE("STGABRPL01");
							ogen.setAUA_CODE("STGABRPL01");
							ogen.setENV_TYPE("PREPROD");
							ogen.setASA_NAME("CDSL");

							int ii = otpgenDao.save(ogen);
							outputresults.put("message", "OTP Flooding - Please avoid trying to generate the OTP multiple times within short time");
							outputresults.put("error", ores.getCode());
							outputresults.put("status", "0");
							return outputresults.toString();

						} else {
							Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
							Log.aua.info("Response Meta Data Details::Staus Message:" + ores.getErr() + "::" + "ResponseTime::" + response_time + "::Status Code:" + ores.getCode() + "::ResTranscation id:" + "");
							otpGeneration ogen = null;
							ogen = new otpGeneration();
							ogen.setUID(Long.parseLong(user.getAadharnumber()));
							ogen.setTRANSACTION_ID(ores.getTxn());
							ogen.setUNIQUE_ID(otpUtransactionId);
							ogen.setSTATUS("0");
							ogen.setOTP_STATUS(2);
							ogen.setMESSAGE(ores.getErr());
							ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
							ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
							ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
							ogen.setERRORCODE(ores.getCode());
							ogen.setSUB_AUA_CODE("STGABRPL01");
							ogen.setAUA_CODE("STGABRPL01");
							ogen.setENV_TYPE("PREPROD");
							ogen.setASA_NAME("CDSL");

							int ii = otpgenDao.save(ogen);
							outputresults.put("message", ores.getErr());
							outputresults.put("error", ores.getCode());
							outputresults.put("status", "0");
							return outputresults.toString();

						}

					}
				} catch (XMLParsingException ex) {

					org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseotpxml, "", Parser.xmlParser());
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");
					ex.getException().printStackTrace();

					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE(ex.getMessage());
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(1);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE(doc.select("Code").text());
					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");

					int ii = otpgenDao.save(ogen);

					outputresults.put("message", ex.getMessage());
					outputresults.put("error", doc.select("Code").text());
					outputresults.put("status", "0");
					return outputresults.toString();

				} catch (InvalidResponseException ex) {

					org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseotpxml, "", Parser.xmlParser());

					ex.getStackTrace();
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE(ex.getMessage());
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(1);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE(doc.select("Code").text());

					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");
					int ii = otpgenDao.save(ogen);

					outputresults.put("message", ex.getMessage());
					outputresults.put("error", doc.select("Code").text());
					outputresults.put("status", "0");
					return outputresults.toString();
				} catch (AsaServerException ex) {

					org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseotpxml, "", Parser.xmlParser());

					ex.getStackTrace();
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE(ex.getMessage());
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(1);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE(doc.select("Code").text());
					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");
					int ii = otpgenDao.save(ogen);

					outputresults.put("message", ex.getMessage());
					outputresults.put("error", doc.select("Code").text());
					outputresults.put("status", "0");
					return outputresults.toString();

				} catch (UidaiSignatureVerificationFailedException ex) {

					org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseotpxml, "", Parser.xmlParser());

					ex.getStackTrace();
					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");

					otpGeneration ogen = null;
					ogen = new otpGeneration();
					ogen.setUID(Long.parseLong(user.getAadharnumber()));
					ogen.setTRANSACTION_ID("");
					ogen.setUNIQUE_ID(otpUtransactionId);
					ogen.setSTATUS("0");
					ogen.setMESSAGE(ex.getMessage());
					ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
					ogen.setOTP_STATUS(1);
					ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					ogen.setERRORCODE(doc.select("Code").text());
					ogen.setSUB_AUA_CODE("STGABRPL01");
					ogen.setAUA_CODE("STGABRPL01");
					ogen.setENV_TYPE("PREPROD");
					ogen.setASA_NAME("CDSL");
					int ii = otpgenDao.save(ogen);

					outputresults.put("message", ex.getMessage());
					outputresults.put("error", doc.select("Code").text());
					outputresults.put("status", "0");
					return outputresults.toString();
				} catch (Exception ex) {

					String respons_time = "";

					Date rsqdate = new Date();
					respons_time = dateFormat.format(rsqdate);

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");
					if (ex.getMessage().contentEquals("Invalid uid")) {

						ex.getStackTrace();

						otpGeneration ogen = null;
						ogen = new otpGeneration();
						ogen.setUID(Long.parseLong(user.getAadharnumber()));
						ogen.setTRANSACTION_ID("");
						ogen.setUNIQUE_ID(otpUtransactionId);
						ogen.setSTATUS("0");
						ogen.setMESSAGE("Invalid Aadhaar Number");
						ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
						ogen.setOTP_STATUS(1);
						ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
						ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
						ogen.setERRORCODE("998");
						ogen.setSUB_AUA_CODE("STGABRPL01");
						ogen.setAUA_CODE("STGABRPL01");
						ogen.setENV_TYPE("PREPROD");
						ogen.setASA_NAME("CDSL");
						int ii = otpgenDao.save(ogen);

						outputresults.put("message", "Invalid Aadhaar Number");
						outputresults.put("error", "998");
						outputresults.put("status", "0");
						return outputresults.toString();

					} else {

						ex.getStackTrace();
						otpGeneration ogen = null;
						ogen = new otpGeneration();
						ogen.setUID(Long.parseLong(user.getAadharnumber()));
						ogen.setTRANSACTION_ID("");
						ogen.setUNIQUE_ID(otpUtransactionId);
						ogen.setSTATUS("0");
						ogen.setMESSAGE("ASA server down!Please contact technical team");
						ogen.setREQUEST_BY(session.getAttribute("user_login_name").toString());
						ogen.setOTP_STATUS(1);
						ogen.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
						ogen.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
						ogen.setERRORCODE("A108");
						ogen.setSUB_AUA_CODE("STGABRPL01");
						ogen.setAUA_CODE("STGABRPL01");
						ogen.setENV_TYPE("PREPROD");
						ogen.setASA_NAME("CDSL");
						int ii = otpgenDao.save(ogen);

						outputresults.put("message", "ASA server down!Please contact technical team");
						outputresults.put("error", "A108");
						outputresults.put("status", "0");
						return outputresults.toString();
					}

				}

			} catch (Exception ex) {

				String response_time = "";

				Date rsqdate = new Date();
				response_time = dateFormat.format(rsqdate);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

				ex.getStackTrace();

				JSONObject outputresults = new JSONObject();
				outputresults.put("message", "ASA server down!Please contact technical team");
				outputresults.put("error", "A108");
				outputresults.put("status", "0");
				return outputresults.toString();
			}

		} else {
			return "";

		}

	}

	/**
	 * Otp process send.
	 *
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
	@RequestMapping(value = "/OtpProcessSend", method = { RequestMethod.POST })
	public @ResponseBody String OtpProcessSend(Model model, HttpServletRequest request, HttpSession session) throws Exception {

		int access = userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(), session);
		String propFilePath = "";
		PREAUAProperties.load();
		if (session.getAttribute("user_login_name") != null && access == 1) {

			DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			Date dateobj = new Date();
			String otpUtransactionId = (String) session.getAttribute("otptranscactionid");

			/**
			 * Getting The Location Of Operator
			 **/

			ClassLoader classLoader = getClass().getClassLoader();

			Properties properties = new Properties();

			ClassLoader classloadererror = Thread.currentThread().getContextClassLoader();
			properties.load(new FileInputStream(new File(classloadererror.getResource("aadhaarErrorCode.properties").getFile())));

			String flocation = "", fpostalcode = "", fcity = "";
			String orgip = AUAUtilities.getClientIpAddr(request);

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

			String request_time = (String) session.getAttribute("request_time");
			String requestXml = "";
			String responseXml = "";

			if (request.getParameter("otp").toString().trim().length() != 6) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Invalid OTP value length is not 6" + "::" + "ResponseTime::" + response_time + "::Status Code:201" + "::ResTranscation id:" + "");
				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("OTPAUTH");
				veri.setMESSAGE("Invalid OTP value length is not 6");
				veri.setERROR_CODE("400");
				veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
				veri.setTRANSACTION_ID(otpUtransactionId);
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setASA_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);
				JSONObject outputresults = new JSONObject();
				outputresults.put("otpbiotransactionnm", "null");
				outputresults.put("status", "0");
				outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
				outputresults.put("otpCode", "");
				outputresults.put("otpmessage", "Invalid OTP value length is not 6");
				return outputresults.toString();
			}
			AuthProcessor pro = new AuthProcessor(PREAUAProperties.readAll(PREAUAProperties.getUidai_encrypt_cert()), PREAUAProperties.readAll(PREAUAProperties.getUidai_signing_cert()));
			pro.setUid(request.getParameter("uid").toString().trim());
			pro.setAc(PREAUAProperties.getUidai_aua_code());
			pro.setSa(PREAUAProperties.getUidai_subaua_code());
			pro.setRc(RcType.Y);
			pro.setTid(TidType.None);
			pro.setLk(PREAUAProperties.getUidai_license_key());
			pro.setTxn(otpUtransactionId);
			pro.prepareOtpPIDBlock(request.getParameter("otp").toString().trim(), "AUT122333");

			try {
				requestXml = pro.getSignedXml(PREAUAProperties.readAll(PREAUAProperties.getClient_pfx()), PREAUAProperties.getClient_password());

				responseXml = HttpConnector.postData(PREAUAProperties.getAsa_request_url(), requestXml);

			} catch (Exception ex) {
				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:" + ex.getMessage() + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");

				if (ex.getMessage().contentEquals("Invalid uid")) {
					ex.printStackTrace();
					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("Invalid Aadhaar Number");
					veri.setERROR_CODE("998");
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID(otpUtransactionId);
					veri.setSERVER_RESPONSE_ON("NA");
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setSTATUS_DESCRIPTION("Authentication Failure");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);
					JSONObject outputresults = new JSONObject();
					outputresults.put("otpbiotransactionnm", "null");
					outputresults.put("status", "0");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("error", "998");
					outputresults.put("otpmessage", "Invalid Aadhaar Number");
					return outputresults.toString();

				} else {

					ex.printStackTrace();
					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("ASA server down!Please contact technical team");
					veri.setERROR_CODE("A108");
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID(otpUtransactionId);
					veri.setSERVER_RESPONSE_ON("NA");
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setSTATUS_DESCRIPTION("Authentication Failure");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);
					JSONObject outputresults = new JSONObject();
					outputresults.put("otpbiotransactionnm", "null");
					outputresults.put("status", "0");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("error", "A108");
					outputresults.put("otpmessage", "ASA server down!Please contact technical team");
					return outputresults.toString();

				}

			}

			JSONObject outputresults = new JSONObject();
			if (responseXml.startsWith("<error>")) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + "");
				outputresults.put("status", "0");
				outputresults.put("otpmessage", "Authentication Failure");
				return outputresults.toString();

			}

			try {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				AuthRes res = pro.parse(responseXml);
				if (res.getRet() == AuthResult.Y) {

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Authentication Success" + "::" + "ResponseTime::" + response_time + "::Status Code:200" + "::ResTranscation id:" + "");
					/// ***VERIFICATION
					/// DETAILS***//

					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("Authentication Success");
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID(res.getTxn());
					veri.setSERVER_RESPONSE_ON(res.getTs());
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
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
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);
					outputresults.put("otpbiotransactionnm", res.getTxn());
					outputresults.put("status", "1");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("otpCode", res.getCode());
					outputresults.put("otpmessage", "Authentication Success");

					return outputresults.toString();

				} else {

					Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
					Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + res.getErr() + "::ResTranscation id:" + "");

					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("Authentication Failure");
					veri.setERROR_CODE(res.getErr());
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID(res.getTxn());
					veri.setSERVER_RESPONSE_ON(res.getTs());
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
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
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);
					outputresults.put("otpbiotransactionnm", res.getTxn());
					outputresults.put("status", "0");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("otpCode", res.getCode());
					outputresults.put("otpmessage", "Authentication Failure" + res.getErr());

					return outputresults.toString();

				}

			} catch (XMLParsingException ex) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);

				ex.getException().printStackTrace();
				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());

				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");
				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("OTPAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(doc.select("Code").text());
				veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setASA_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				outputresults.put("otpbiotransactionnm", doc.select("txn").text());
				outputresults.put("status", "0");
				outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
				outputresults.put("error", doc.select("Code").text());
				outputresults.put("otpmessage", ex.getMessage());

				return outputresults.toString();

			} catch (AsaServerException ex) {

				Log.aua.info("Response Message For OTP Authentication::" + ex.getMessage());

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);
				ex.printStackTrace();
				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");
				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("OTPAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(doc.select("Code").text());
				veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setASA_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				outputresults.put("otpbiotransactionnm", doc.select("txn").text());
				outputresults.put("status", "0");
				outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
				outputresults.put("error", doc.select("Code").text());
				outputresults.put("otpmessage", ex.getMessage());

				return outputresults.toString();

			} catch (InvalidResponseException ex) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);
				ex.printStackTrace();
				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");
				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("OTPAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(doc.select("Code").text());
				veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setASA_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				outputresults.put("otpbiotransactionnm", doc.select("txn").text());
				outputresults.put("status", "0");
				outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
				outputresults.put("error", doc.select("Code").text());
				outputresults.put("otpmessage", ex.getMessage());
				return outputresults.toString();
			} catch (UidaiSignatureVerificationFailedException ex) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);
				ex.printStackTrace();
				org.jsoup.nodes.Document doc = Jsoup.parse("<?xml version=\"1.0\" encoding=\"UTF-8\">" + responseXml, "", Parser.xmlParser());
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + doc.select("Code").text() + "::ResTranscation id:" + "");
				Verification veri = null;
				veri = new Verification();
				veri.setAPI_NAME("2.0");
				veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
				veri.setAUTH_TYPE("OTPAUTH");
				veri.setMESSAGE("Authentication Failure");
				veri.setERROR_CODE(doc.select("Code").text());
				veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
				veri.setTRANSACTION_ID("NA");
				veri.setSERVER_RESPONSE_ON("NA");
				veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
				veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
				veri.setCOUNTRY(flocation);
				veri.setIPADDRESS(orgip);
				veri.setCITY(fcity);
				veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
				veri.setSTATUS(0);
				veri.setSTATUS_DESCRIPTION("Authentication Failure");
				veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
				veri.setCONSENT(1);
				veri.setENV_TYPE("PREPROD");
				veri.setASA_NAME("CDSL");
				int verificationid = verificationDAO.save(veri);

				outputresults.put("otpbiotransactionnm", doc.select("txn").text());
				outputresults.put("status", "0");
				outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
				outputresults.put("error", doc.select("Code").text());
				outputresults.put("otpmessage", ex.getMessage());
				return outputresults.toString();
			} catch (Exception ex) {

				String response_time = "";
				DateFormat dateFormat1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
				Date reqdate1 = new Date();
				response_time = dateFormat1.format(reqdate1);
				Log.aua.info("Request Meta Data Details:" + "AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "SUB AUA Code::" + PREAUAProperties.uidai_aua_code + "::" + "ReqTransactionId::" + otpUtransactionId + "::" + "RequestTime::" + request_time + "::" + "API Name::" + "2.0");
				Log.aua.info("Response Meta Data Details::Staus Message:Authentication Failure" + "::" + "ResponseTime::" + response_time + "::Status Code:" + "::ResTranscation id:" + "");
				if (ex.getMessage().contentEquals("Invalid uid")) {
					ex.printStackTrace();
					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("Invalid Aadhaar Number");
					veri.setERROR_CODE("998");
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID("NA");
					veri.setSERVER_RESPONSE_ON("NA");
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setSTATUS_DESCRIPTION("Authentication Failure");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);

					outputresults.put("otpbiotransactionnm", "null");
					outputresults.put("status", "0");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("error", "998");
					outputresults.put("otpmessage", "Invalid Aadhaar Number");

					return outputresults.toString();
				} else {

					ex.printStackTrace();
					Verification veri = null;
					veri = new Verification();
					veri.setAPI_NAME("2.0");
					veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setSUB_AUA_CODE(PREAUAProperties.getUidai_aua_code());
					veri.setAUTH_TYPE("OTPAUTH");
					veri.setMESSAGE("ASA server down!Please contact technical team");
					veri.setERROR_CODE("A108");
					veri.setUID(Long.parseLong((String) session.getAttribute("otpaadhaarnumber")));
					veri.setTRANSACTION_ID("NA");
					veri.setSERVER_RESPONSE_ON("NA");
					veri.setREQUEST_ON(new Timestamp(dateFormat1.parse(request_time).getTime()));
					veri.setRESPONSE_ON(new Timestamp(dateFormat1.parse(response_time).getTime()));
					veri.setCOUNTRY(flocation);
					veri.setIPADDRESS(orgip);
					veri.setCITY(fcity);
					veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
					veri.setSTATUS(0);
					veri.setSTATUS_DESCRIPTION("Authentication Failure");
					veri.setREQUESTED_BY(session.getAttribute("user_login_name").toString());
					veri.setCONSENT(1);
					veri.setENV_TYPE("PREPROD");
					veri.setASA_NAME("CDSL");
					int verificationid = verificationDAO.save(veri);
					outputresults.put("otpbiotransactionnm", "null");
					outputresults.put("status", "0");
					outputresults.put("aadhaar", request.getParameter("uid").toString().trim());
					outputresults.put("error", "A108");
					outputresults.put("otpmessage", "ASA server down!Please contact technical team");
					return outputresults.toString();
				}
			}
		} else {
			return "";
		}
	}

}
