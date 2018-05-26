package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.Verification;

@Repository
@Transactional
public class VerificationDAOImpl implements VerificationDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public Verification getByVerification_ID(int ID) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();

		Criteria criteria = (Criteria) session.get(Verification.class, ID);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return (Verification) criteria;

	}

	@SuppressWarnings("unchecked")
	public List<Verification> getAllVerification() {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = session.createCriteria(Verification.class);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria.list();

	}

	public int save(Verification verification) {


		// TODO Auto-generated method stub
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Integer criteria = (Integer) session.save(verification);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria;
	}

	public void update(Verification verification) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(verification);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

	}

	public void view(Verification verification) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(verification);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

	}

	public void delete(int ID) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Verification v = getByVerification_ID(ID);
		sessionFactory.getCurrentSession().delete(v);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

	}

	@Override
	public int getAccesslimit(String clientid) {
		// TODO Auto-generated method stub
		Criteria query = sessionFactory.getCurrentSession().createCriteria(Verification.class);
		query.add(Restrictions.eq("REQUESTED_BY", clientid));
		query.add(Restrictions.ne("STATUS", 2));
		query.setProjection(Projections.rowCount());
		Integer count = (Integer) query.uniqueResult();
		return count;
	}

}
