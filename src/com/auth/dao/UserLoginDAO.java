package com.auth.dao;

import javax.servlet.http.HttpSession;

import org.hibernate.HibernateException;

/** 
 * Interface for user Login
 * 
 * */
public interface UserLoginDAO {

	/**
	 * Checks if is acess details.
	 *
	 * @param username
	 *            the username
	 * @param session
	 *            the session
	 * @return the int
	 * @throws Exception
	 *             the exception
	 */
	public int isAcessDetails(String username,HttpSession session);
	
	
	/**
	 * Checks if is pass expire.
	 *
	 * @param username
	 *            the username
	 * @param password
	 *            the password
	 * @param session
	 *            the session
	 * @return the int
	 * @throws HibernateException 
	 * @throws Exception
	 *             the exception
	 */
	public int isPassExpire(String username, String password, HttpSession session) throws HibernateException, Exception;
	
	
	/**
	 * Checks if is pass chaange.
	 *
	 * @param oldpassword
	 *            the oldpassword
	 * @param newpassowrd
	 *            the newpassowrd
	 * @param username
	 *            the username
	 * @return the int
	 * @throws Exception
	 *             the exception
	 */
	public int isPassChaange(String oldpassword, String newpassowrd, String username) throws Exception;
	
	
	/**
	 * Checks if is update valid user.
	 *
	 * @param username
	 *            the username
	 * @param oldpassword
	 *            the oldpassword
	 * @param newpassword
	 *            the newpassword
	 * @param session
	 *            the session
	 * @return the int
	 * @throws Exception
	 *             the exception
	 */
	public int isUpdateValidUser(String username, String oldpassword, String newpassword, HttpSession session) throws Exception;
	
	/**
	 * Checks if is update authorization key.
	 *
	 * @param uid
	 *            the uid
	 * @param auth_key
	 *            the auth key
	 * @param user_name
	 *            the user name
	 * @return the int
	 */
	public int isUpdateAuthorizationKey(String uid, String auth_key, String user_name);
	
	/**
	 * Checks if is aadhaar.
	 *
	 * @param uid
	 *            the uid
	 * @param user_name
	 *            the user name
	 * @return the int
	 */
	public int isAadhaar(String uid, String user_name);
	
	/**
	 * Checks if is valid authorization key.
	 *
	 * @param uid
	 *            the uid
	 * @param auth_key
	 *            the auth key
	 * @param user_name
	 *            the user name
	 * @return the int
	 */
	public int isValidAuthorizationKey(String uid, String auth_key, String user_name);
	
	
	/**
	 * Gets the aadhaar number.
	 *
	 * @param opratorusername
	 *            the opratorusername
	 * @return the aadhaar number
	 */
	public int getaadhaarNumber(String opratorusername);
	
	
	/**
	 * Checks if is change valid user.
	 *
	 * @param username
	 *            the username
	 * @param oldpassword
	 *            the oldpassword
	 * @param newpassword
	 *            the newpassword
	 * @param session
	 *            the session
	 * @return the int
	 * @throws Exception
	 *             the exception
	 */
	public int isChangeValidUser(String username, String oldpassword, String newpassword, HttpSession session) throws Exception;
	
	/**
	 * Checks if is valid user.
	 *
	 * @param username
	 *            the username
	 * @param password
	 *            the password
	 * @param session
	 *            the session
	 * @return the int
	 * @throws HibernateException 
	 * @throws Exception
	 *             the exception
	 */
	public boolean isValidUser(String username, String password, HttpSession session) throws HibernateException, Exception;
	
	
	
}
