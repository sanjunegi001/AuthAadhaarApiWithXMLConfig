package com.auth.service;

import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.stereotype.Service;

import com.auth.bean.Verification;
import com.auth.bean.otpGeneration;
import com.auth.dao.OtpGenDAO;
import com.auth.dao.VerificationDAO;
import com.auth.util.PREAUAProperties;

import in.gov.uidai.authentication.otp_response._1.OtpRes;
import in.gov.uidai.authentication.uid_auth_response._1.AuthRes;

@Service
@Configurable
public class OtpSerivce {
	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

	@Autowired
	private OtpGenDAO otpgenDAO;

	@Autowired
	private VerificationDAO verificationDAO;

	public void saveOtpGen(OtpRes ores, String msg, String aadharcardnumber, String utransactionId, String request_time, String response_time, String subAuaCode, String username) throws ParseException {

		otpGeneration ogen = new otpGeneration();

		if (StringUtils.isNotEmpty(ores.getErr())) {
			ogen.setSTATUS("0");
			ogen.setOTP_STATUS(2);
			ogen.setERRORCODE(ores.getErr());
		} else {
			ogen.setSTATUS("1");
			ogen.setOTP_STATUS(0);
			ogen.setERRORCODE("");
		}
		ogen.setUID(Long.parseLong(aadharcardnumber));
		ogen.setTRANSACTION_ID(ores.getTxn());
		ogen.setUNIQUE_ID(utransactionId);
		ogen.setMESSAGE(msg);
		ogen.setREQUEST_BY(username);
		ogen.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
		ogen.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
		ogen.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
		ogen.setSUB_AUA_CODE(subAuaCode);
		ogen.setASA_NAME("CDSL");
		ogen.setENV_TYPE("PREPROD");
		int ii = otpgenDAO.save(ogen);

	}

	public void errorOtpGen(String username, String errmsg, String errocode, String request_time, String response_time) throws ParseException {

		otpGeneration ogen = new otpGeneration();
		ogen.setUID(Long.parseLong(""));
		ogen.setTRANSACTION_ID("");
		ogen.setUNIQUE_ID("");
		ogen.setSTATUS("0");
		ogen.setMESSAGE(errmsg);
		ogen.setREQUEST_BY(username);
		ogen.setOTP_STATUS(1);
		ogen.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
		ogen.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
		ogen.setERRORCODE(errocode);
		ogen.setASA_NAME("CDSL");
		ogen.setENV_TYPE("PREPROD");
		int ii = otpgenDAO.save(ogen);
	}

	public void saveOtpVer(AuthRes authres, String aadharcardnumber, String request_time, String response_time, String flocation, String orgip, String fcity, String fpostalcode, String subAuaCode, String username) throws ParseException {

		Verification veri = new Verification();
		veri.setAPI_NAME("2.0");
		veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
		veri.setSUB_AUA_CODE(subAuaCode);
		veri.setAUTH_TYPE("OTPAUTH");

		if (StringUtils.isNotEmpty(authres.getErr())) {
			veri.setMESSAGE("Authentication Failure");
			veri.setSTATUS(0);
		} else {
			veri.setMESSAGE("Authentication Success");
			veri.setSTATUS(1);
		}

		veri.setUID(Long.parseLong(aadharcardnumber));
		veri.setUDC_CODE("AUT123");
		veri.setERROR_CODE(authres.getErr());
		veri.setTRANSACTION_ID(authres.getTxn());
		veri.setSERVER_RESPONSE_ON(authres.getTs());
		veri.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
		veri.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
		veri.setCOUNTRY(flocation);
		veri.setIPADDRESS(orgip);
		veri.setCITY(fcity);
		veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
		veri.setREFERENCE_NUMBER(authres.getCode());
		veri.setREQUESTED_BY(username.toString());
		veri.setCONSENT(1);
		veri.setENV_TYPE("PREPROD");
		veri.setASA_NAME("CDSL");
		verificationDAO.save(veri);
	}

	public void saveExceptionGenOtp(String errorCode, String errorMessage, String aadharcardnumber, String request_time, String response_time, String flocation, String orgip, String fcity, String fpostalcode, String subAuaCode, String username) throws ParseException {

		otpGeneration ogen = new otpGeneration();
		ogen.setSTATUS("0");
		ogen.setOTP_STATUS(2);
		ogen.setERRORCODE(errorCode);
		ogen.setUID(Long.parseLong(aadharcardnumber));
		ogen.setTRANSACTION_ID("");
		ogen.setUNIQUE_ID("");
		ogen.setMESSAGE(errorMessage);
		ogen.setREQUEST_BY(username);
		ogen.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
		ogen.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
		ogen.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
		ogen.setSUB_AUA_CODE(subAuaCode);
		ogen.setASA_NAME("CDSL");
		ogen.setENV_TYPE("PREPROD");

		int ii = otpgenDAO.save(ogen);

	}

	public void saveExceptionOtp(String errorCode, String errorMessage, String aadharcardnumber, String request_time, String response_time, String flocation, String orgip, String fcity, String fpostalcode, String subAuaCode, String username) throws ParseException {

		Verification veri = new Verification();

		veri.setAPI_NAME("2.0");
		veri.setAUA_CODE(PREAUAProperties.getUidai_aua_code());
		veri.setSUB_AUA_CODE(subAuaCode);
		veri.setAUTH_TYPE("OTPAUTH");

		veri.setUID(Long.parseLong(aadharcardnumber));
		veri.setERROR_CODE(errorCode);
		veri.setREQUEST_ON(new Timestamp(dateFormat.parse(request_time).getTime()));
		veri.setRESPONSE_ON(new Timestamp(dateFormat.parse(response_time).getTime()));
		veri.setCOUNTRY(flocation);
		veri.setIPADDRESS(orgip);
		veri.setCITY(fcity);
		veri.setPINCODE(Integer.parseInt(fpostalcode.trim()));
		veri.setMESSAGE("Authentication Failure");
		veri.setSTATUS_DESCRIPTION(errorMessage);
		veri.setSTATUS(0);
		veri.setREQUESTED_BY(username.toString());
		veri.setCONSENT(1);
		veri.setENV_TYPE("PREPROD");
		veri.setASA_NAME("CDSL");

		verificationDAO.save(veri);
	}

}
