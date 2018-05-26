package com.auth.dao;

import java.util.List;

import com.auth.bean.otpGeneration;;

public interface OtpGenDAO {

	otpGeneration getByOtp_ID(int Otp_Id);

	int save(otpGeneration otpgeneration);

	void update(otpGeneration otpgeneration);

	void view(otpGeneration otpgeneration);

	int updateOtpgen(String clientid, String tranId);

	List<otpGeneration> getDuplicate_ID(String clientid, String uniqueid);

	List<otpGeneration> getaadhaarNumber(String uniqueid, String clientid);

	void delete(int OTP_ID);
}
