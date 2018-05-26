package com.auth.dao;

import java.util.List;

import com.auth.bean.Residential;

public interface ResidentialDAO {

	Residential getByResidential_ID(int Residential_ID);

	List<Residential> getAllResidential();

	int save(Residential residential);

	void update(Residential residential);

	void view(Residential residential);

	void delete(int Residential_ID);

}
