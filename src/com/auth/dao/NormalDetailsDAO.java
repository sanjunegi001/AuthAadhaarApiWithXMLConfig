package com.auth.dao;

import java.util.List;

import com.auth.bean.normalAuthDetails;

public interface NormalDetailsDAO {

	normalAuthDetails getOneById(String clientid);
	
	List<normalAuthDetails> getByUrlID(String clientid);

	List<normalAuthDetails> getAllContact();

	List<normalAuthDetails> getListUrl(String name);

	int save(normalAuthDetails contact);

	void update(normalAuthDetails contact);

	void view(normalAuthDetails contact);
}
