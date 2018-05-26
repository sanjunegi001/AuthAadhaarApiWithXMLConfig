package com.auth.dao;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import org.hibernate.Criteria;
import org.hibernate.HibernateException;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.util.MD5Auth;
import com.auth.bean.*;

@Repository
@Transactional
public class UserLoginDAOImpl implements UserLoginDAO {

	@Autowired
	private SessionFactory sessionFactory;

	/** The data source. */
	@Autowired
	DataSource dataSource;

	/**
	 * Gets the data source.
	 *
	 * @return the data source
	 */
	public DataSource getDataSource() {
		return this.dataSource;
	}

	/**
	 * Sets the data source.
	 *
	 * @param dataSource
	 *            the new data source
	 */
	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	/*
	 * Method for get user access details Mandatory @param is username
	 */
	@Override
	public int isAcessDetails(String username, HttpSession session) {

		int result = 0;
		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		List<userLogin> usellist = criteria.list();

		if ((usellist != null) && (usellist.size() > 0)) {
			for (userLogin usellists : usellist) {
				result = usellists.getUser_access_flag();

			}

		}
		sess.close();
		return result;
	}

	/*
	 * Method for checking password expire Mandatory @param are username and
	 * password
	 */
	@Override
	public int isPassExpire(String username, String password, HttpSession session)
			throws HibernateException, Exception {

		int result = 0;
		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		criteria.add(Restrictions.eq("user_password", mdauth.encode(password).trim()));
		List<userLogin> userlist = criteria.list();

		if ((userlist != null) && (userlist.size() > 0)) {
			Calendar cal = Calendar.getInstance();
			Date today = cal.getTime();
			for (userLogin userlists : userlist) {

				if (today.after(userlists.getUser_expired_on())) {

					result = 0;
					return result;
				} else {

					result = 1;
					return result;
				}

			}

		}

		sess.close();
		return result;

	}

	/*
	 * Method for change the password Mandatory @param are username and
	 * oldpassword and new passowrd
	 */
	@Override
	public int isPassChaange(String oldpassword, String newpassowrd, String username) throws Exception {

		MD5Auth mdauth = new MD5Auth();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date date = new Date();

		Calendar c = Calendar.getInstance();
		c.setTime(new Date()); // Now use today date.
		c.add(Calendar.DATE, 90); // Adding 90 days
		String expireddate = dateFormat.format(c.getTime());

		int result = 0;
		Session sess = sessionFactory.openSession();
		Transaction tx = sess.beginTransaction();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		criteria.add(Restrictions.eq("user_password", mdauth.encode(oldpassword).trim()));
		List<userLogin> userlist = criteria.list();
		if ((userlist != null) && (userlist.size() > 0)) {
			userLogin e = (userLogin) criteria.uniqueResult();
			e.setUser_password(mdauth.encode(newpassowrd).trim());
			e.setLast_password_changed(dateFormat.parse(dateFormat.format(date)));
			e.setUser_expired_on(dateFormat.parse(expireddate));
			sess.saveOrUpdate(e);
			tx.commit();
			return 1;
		} else
			return 0;
	}

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
	@Override
	public int isUpdateValidUser(String username, String oldpassword, String newpassword, HttpSession session)
			throws Exception {
		// TODO Auto-generated method stub
		MD5Auth mdauth = new MD5Auth();
		// String encryptedHash = app.encode(oldpassword);

		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date date = new Date();
		System.out.println("curent format date" + dateFormat.format(date));

		Calendar c = Calendar.getInstance();
		c.setTime(new Date()); // Now use today date.
		c.add(Calendar.DATE, 90); // Adding 90 days
		String expireddate = dateFormat.format(c.getTime());

		int result1 = 0;

		Session sess = sessionFactory.openSession();
		Transaction tx = sess.beginTransaction();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		criteria.add(Restrictions.eq("user_password", mdauth.encode(oldpassword).trim()));
		List<userLogin> userlist = criteria.list();
		if ((userlist != null) && (userlist.size() > 0)) {
			userLogin e = (userLogin) criteria.uniqueResult();
			e.setUser_password(mdauth.encode(newpassword).trim());
			e.setLast_password_changed(dateFormat.parse(dateFormat.format(date)));
			e.setUser_expired_on(dateFormat.parse(expireddate));
			sess.saveOrUpdate(e);
			tx.commit();
			return 1;
		} else
			return 0;

	}

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
	@Override
	public int isUpdateAuthorizationKey(String uid, String auth_key, String user_name) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int isAadhaar(String uid, String user_name) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int isValidAuthorizationKey(String uid, String auth_key, String user_name) {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * Gets the aadhaar number.
	 *
	 * @param opratorusername
	 *            the opratorusername
	 * @return the aadhaar number
	 */
	@Override
	public int getaadhaarNumber(String opratorusername) {
		int result2 = 0;

		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", opratorusername.trim()));
		criteria.setProjection(Projections.rowCount());
		if ((Integer) criteria.uniqueResult() > 0) {
			return 1;
		} else {
			return 0;
		}
	}

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
	@Override
	public int isChangeValidUser(String username, String oldpassword, String newpassword, HttpSession session) throws Exception {
		int result2 = 0;

		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		criteria.add(Restrictions.eq("user_password", mdauth.encode(oldpassword).trim()));
		criteria.setProjection(Projections.rowCount());
		if ((Integer) criteria.uniqueResult() > 0) {
			return 1;
		} else {
			return 0;
		}
		
	}

	/*
	 * Method for user validation Mandatory @param username ,password set
	 * session values
	 */
	@Override
	public boolean isValidUser(String username, String password, HttpSession session)
			throws HibernateException, Exception {

		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(userLogin.class);
		criteria.add(Restrictions.eq("user_loginname", username.trim()));
		criteria.add(Restrictions.eq("user_password", mdauth.encode(password).trim()));
		List<userLogin> result = criteria.list();
		criteria.setProjection(Projections.rowCount());

		if ((Integer) criteria.uniqueResult() > 0) {

			for (userLogin results : result) {
				if (results.getUser_aadhaar_number() != null) {
					session.setAttribute("operator_aadhaar_number", results.getUser_aadhaar_number());

					session.setAttribute("user_secret_flag", results.getUser_flag());
				} else {
					session.setAttribute("operator_aadhaar_number", "0");
					session.setAttribute("user_secret_flag", results.getUser_flag());
				}
				session.setAttribute("user_login_name", results.getUser_loginname());
			}
			sess.close();
			return true;
		} else {
			sess.close();
			return false;
		}

	}

}
