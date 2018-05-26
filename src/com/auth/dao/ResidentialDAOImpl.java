package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.Residential;
import com.auth.bean.deviceDetails;

@Repository
@Transactional
public class ResidentialDAOImpl implements ResidentialDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public Residential getByResidential_ID(int Residential_ID) {
		
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();

		Criteria criteria = (Criteria) session.get(Residential.class, Residential_ID);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return (Residential) criteria;
		
	}

	public List<Residential> getAllResidential() {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = session.createCriteria(Residential.class);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria.list();
	
	}

	public int save(Residential residential) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Integer criteria = (Integer) session.save(residential);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria;
	}

	public void update(Residential residential) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(residential);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

	}

	public void view(Residential residential) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(residential);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();

	}

	public void delete(int Residential_ID) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Residential r = getByResidential_ID(Residential_ID);
		sessionFactory.getCurrentSession().delete(r);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		

	}

}
