package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.Personal;
import com.auth.bean.deviceDetails;

@Repository
@Transactional
public class PersonalDAOImpl implements PersonalDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public Personal getByPersonal_ID(int Personal_ID) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();

		Criteria criteria = (Criteria) session.get(Personal.class, Personal_ID);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return (Personal) criteria;
		
	}

	public List<Personal> getAllPersonal() {
		
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Personal.class);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria.list();
		
	}

	public int save(Personal personal) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Integer criteria = (Integer) session.save(personal);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		return criteria;
	}

	public void update(Personal personal) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(personal);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		

	}

	public void view(Personal personal) {
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria criteria = (Criteria) session.merge(personal);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		

	}

	public void delete(int Personal_ID) {
		Personal p = getByPersonal_ID(Personal_ID);
		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		sessionFactory.getCurrentSession().delete(p);
		session.flush();
		session.clear();
		tx.commit();
		session.close();
		sessionFactory.close();
		

	}

}
