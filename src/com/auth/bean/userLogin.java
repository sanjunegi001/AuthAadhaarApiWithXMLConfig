package com.auth.bean;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

//bean class for user details
@Entity
@Table(name = "ab_user_details")
public class userLogin {

	
	/** The id. */
	@Id
	@GeneratedValue
	private int user_id;
	
	/** The user name. */
	@Column
	private String user_loginname;
	
	/** The user password. */
	@Column
	private String user_password;
	
	/** The user first name. */
	@Column
	private String user_first_name;
	
	
	/** The user last name. */
	@Column
	private String user_last_name;
	
	/** The date of usr create. */
	@Column
	private Date user_created_on;
	
	/** The date of last  change. */
	@Column
	private Date last_password_changed;
	
	/** The date of user expire. */
	@Column
	private Date user_expired_on;
	
	/** The user mob number. */
	@Column
	private String user_mob;
	
	/** The user name. */
	@Column
	private String user_aadhaar_number;
	
	/** The flag for access. */
	@Column
	private int user_access_flag;
	
	/** The user flag. */
	@Column
	private int user_flag;

	public int getUser_id() {
		return user_id;
	}

	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}

	public String getUser_loginname() {
		return user_loginname;
	}

	public void setUser_loginname(String user_loginname) {
		this.user_loginname = user_loginname;
	}

	public String getUser_password() {
		return user_password;
	}

	public void setUser_password(String user_password) {
		this.user_password = user_password;
	}

	public String getUser_first_name() {
		return user_first_name;
	}

	public void setUser_first_name(String user_first_name) {
		this.user_first_name = user_first_name;
	}

	public String getUser_last_name() {
		return user_last_name;
	}

	public void setUser_last_name(String user_last_name) {
		this.user_last_name = user_last_name;
	}

	public Date getUser_created_on() {
		return user_created_on;
	}

	public void setUser_created_on(Date user_created_on) {
		this.user_created_on = user_created_on;
	}

	public Date getLast_password_changed() {
		return last_password_changed;
	}

	public void setLast_password_changed(Date last_password_changed) {
		this.last_password_changed = last_password_changed;
	}

	public Date getUser_expired_on() {
		return user_expired_on;
	}

	public void setUser_expired_on(Date user_expired_on) {
		this.user_expired_on = user_expired_on;
	}

	public String getUser_mob() {
		return user_mob;
	}

	public void setUser_mob(String user_mob) {
		this.user_mob = user_mob;
	}

	public String getUser_aadhaar_number() {
		return user_aadhaar_number;
	}

	public void setUser_aadhaar_number(String user_aadhaar_number) {
		this.user_aadhaar_number = user_aadhaar_number;
	}

	public int getUser_access_flag() {
		return user_access_flag;
	}

	public void setUser_access_flag(int user_access_flag) {
		this.user_access_flag = user_access_flag;
	}

	public int getUser_flag() {
		return user_flag;
	}

	public void setUser_flag(int user_flag) {
		this.user_flag = user_flag;
	}
	
	
	
	
}
