package com.auth.bean;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

@Entity
@Table(name = "ab_normal_auth_details")
public class normalAuthDetails {
	
	@Id
	@SequenceGenerator(name = "seq_verification", sequenceName = "seq_verification")
	@GeneratedValue(strategy = GenerationType.AUTO, generator = "seq_verification")
	private int id;
	
	
	@Column
	private String client_id;
	
	@Column
	private String client_name;
	
	@Column
	private String aut_token;
	
	@Column
	private String client_limit;
	
	@Column
	private String active_status;
	
	@Column
	private String response_data;
	
	@Column
	private String client_type;
	
	@Column
	private String dateadded;
	
	
	public normalAuthDetails() {

	}

	
	public normalAuthDetails(int id, String client_id, String client_name, String aut_token, String client_limit,
			String active_status, String response_data, String client_type,String dateadded) {

		this.id = id;
		this.client_id = client_id;
		this.client_name = client_name;
		this.aut_token = aut_token;
		this.client_limit = client_limit;
		this.active_status = active_status;
		this.response_data = response_data;
		this.client_type = client_type;
		this.dateadded=dateadded;

	}


	public String getClient_id() {
		return client_id;
	}


	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}


	public String getClient_name() {
		return client_name;
	}


	public void setClient_name(String client_name) {
		this.client_name = client_name;
	}


	public String getAut_token() {
		return aut_token;
	}


	public void setAut_token(String aut_token) {
		this.aut_token = aut_token;
	}


	public String getClient_limit() {
		return client_limit;
	}


	public void setClient_limit(String client_limit) {
		this.client_limit = client_limit;
	}


	public String getActive_status() {
		return active_status;
	}


	public void setActive_status(String active_status) {
		this.active_status = active_status;
	}


	public String getResponse_data() {
		return response_data;
	}


	public void setResponse_data(String response_data) {
		this.response_data = response_data;
	}


	public String getClient_type() {
		return client_type;
	}


	public void setClient_type(String client_type) {
		this.client_type = client_type;
	}


	public String getDateadded() {
		return dateadded;
	}


	public void setDateadded(String dateadded) {
		this.dateadded = dateadded;
	}
	
	
}
