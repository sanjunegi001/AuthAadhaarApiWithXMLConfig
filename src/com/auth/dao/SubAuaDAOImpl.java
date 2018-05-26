package com.auth.dao;

import java.util.List;

import javax.sql.DataSource;

import org.hibernate.Criteria;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Criterion;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.subAua;
import com.auth.util.MD5Auth;

@Repository
@Transactional

public class SubAuaDAOImpl implements SubAuaDAO {

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

	public subAua getSubAUA(String scode) {

		Criteria query = sessionFactory.getCurrentSession().createCriteria(subAua.class);
		Criterion cn = Restrictions.eq("client_id", scode);
		Criterion cn1 = Restrictions.eq("pre_active_status", 1);
		Criterion cn2 = Restrictions.eq("env_type", "preprod");
		query.add(cn);
		query.add(cn1);
		query.add(cn2);
		return (subAua) query.uniqueResult();
	}

	@Override
	public boolean isValidClient(String username, String password) throws HibernateException, Exception {

		MD5Auth mdauth = new MD5Auth();
		Session sess = sessionFactory.openSession();
		Criteria criteria = sess.createCriteria(subAua.class);
		criteria.add(Restrictions.eq("client_id", username.trim()));
		criteria.add(Restrictions.eq("client_password", mdauth.encode(password).trim()));
		criteria.add(Restrictions.eq("env_type", "preprod"));
		List<subAua> result = criteria.list();
		criteria.setProjection(Projections.rowCount());

		if ((Integer) criteria.uniqueResult() > 0) {
			return true;
		} else {
			return false;
		}

	}

}
