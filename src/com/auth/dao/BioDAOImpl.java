package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.deviceDetails;

@Repository
@Transactional
public class BioDAOImpl implements BioDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public deviceDetails getByDevice_ID(int Device_ID) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();

		Criteria criteria = (Criteria) session.get(deviceDetails.class, Device_ID);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return (deviceDetails) criteria;
		// return (deviceDetails)
		// sessionFactory.getCurrentSession().get(deviceDetails.class,
		// Device_ID);

	}

	public List<deviceDetails> getAllDevice() {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = session.createCriteria(deviceDetails.class);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria.list();

		// Criteria criteria =
		// sessionFactory.getCurrentSession().createCriteria(deviceDetails.class);
		// return criteria.list();

	}

	public int save(deviceDetails device) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Integer criteria = (Integer) session.save(device);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria;

		// return (Integer) sessionFactory.getCurrentSession().save(device);
	}

	public void update(deviceDetails device) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(device);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		// sessionFactory.getCurrentSession().merge(device);

	}

	public void view(deviceDetails device) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(device);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

		// sessionFactory.getCurrentSession().merge(device);

	}

	public int isValidDevice(String udc) throws HibernateException, Exception {

		System.out.println("udc code" + udc);

		int result = 0;
		Session sess = sessionFactory.openSession();
		Transaction tx = sess.beginTransaction();
		Criteria criteria = sess.createCriteria(deviceDetails.class);
		criteria.add(Restrictions.eq("UDC", udc));
		List<deviceDetails> devicelist = criteria.list();

		if ((devicelist != null) && (devicelist.size() > 0)) {

			for (deviceDetails devicelists : devicelist) {
				if (devicelists.getUDC() != null) {

					result = 1;
					return result;
				} else {
					result = 0;
					return result;
				}

			}

		}

		sess.flush();
		sess.clear();
		tx.commit();
		sess.close();
		sessionFactory.close();
		return result;
	}

}
