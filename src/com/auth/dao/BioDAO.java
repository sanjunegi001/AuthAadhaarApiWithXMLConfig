package com.auth.dao;

import java.util.List;

import org.hibernate.HibernateException;

import com.auth.bean.deviceDetails;;

public interface BioDAO {

	deviceDetails getByDevice_ID(int Device_ID);

	List<deviceDetails> getAllDevice();

	int save(deviceDetails device);

	void update(deviceDetails device);

	void view(deviceDetails device);

	public int isValidDevice(String udc) throws HibernateException, Exception;

}
