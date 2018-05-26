package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Criterion;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.normalAuthDetails;

@Repository
@Transactional
public class NormalDetailsDAOImpl implements NormalDetailsDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public List<normalAuthDetails> getByUrlID(String client_id) {

		Criteria query = sessionFactory.getCurrentSession().createCriteria(normalAuthDetails.class);
		Criterion cn = Restrictions.eq("client_id", client_id);
		Criterion cn1 = Restrictions.eq("active_status", "1");
		query.add(cn);
		query.add(cn1);
		return query.list();
	}

	public List<normalAuthDetails> getListUrl(String name) {
		Criteria query = sessionFactory.getCurrentSession().createCriteria(normalAuthDetails.class);
		Criterion cn = Restrictions.eq("client_id", name);
		query.add(cn);
		return query.list();

	}

	public List<normalAuthDetails> getAllContact() {
		Criteria criteria = sessionFactory.getCurrentSession().createCriteria(normalAuthDetails.class);
		return criteria.list();
	}

	public int save(normalAuthDetails naccess) {
		return (Integer) sessionFactory.getCurrentSession().save(naccess);
	}

	public void update(normalAuthDetails naccess) {
		sessionFactory.getCurrentSession().merge(naccess);
	}

	public void view(normalAuthDetails naccess) {
		sessionFactory.getCurrentSession().merge(naccess);

	}

	@Override
	public normalAuthDetails getOneById(String clientid) {
		// TODO Auto-generated method stub

		Criteria query = sessionFactory.getCurrentSession().createCriteria(normalAuthDetails.class);
		Criterion cn = Restrictions.eq("client_id", clientid);
		Criterion cn1 = Restrictions.eq("active_status", "1");
		query.add(cn);
		query.add(cn1);
		return (normalAuthDetails) query.uniqueResult();
	}

}
