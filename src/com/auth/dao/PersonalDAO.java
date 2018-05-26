package com.auth.dao;

import java.util.List;

import com.auth.bean.Personal;

public interface PersonalDAO {

	Personal getByPersonal_ID(int Personal_ID);

	List<Personal> getAllPersonal();

	int save(Personal personal);

	void update(Personal personal);

	void view(Personal personal);

	void delete(int Personal_ID);

}
