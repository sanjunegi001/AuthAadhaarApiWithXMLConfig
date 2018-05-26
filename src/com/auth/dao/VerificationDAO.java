package com.auth.dao;

import java.util.List;

import com.auth.bean.Verification;

public interface VerificationDAO {

	Verification getByVerification_ID(int ID);

	List<Verification> getAllVerification();

	int save(Verification verification);

	void update(Verification verification);

	void view(Verification verification);
	
	public int getAccesslimit(String clientid);

	void delete(int ID);

}
