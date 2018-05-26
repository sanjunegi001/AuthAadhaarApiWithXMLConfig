package com.auth.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.criterion.Criterion;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.auth.bean.otpGeneration;

@Repository
@Transactional
public class OtpGenDAOImpl implements OtpGenDAO {

	@Autowired
	private SessionFactory sessionFactory;

	public void delete(int OTP_ID) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		otpGeneration O = getByOtp_ID(OTP_ID);
		sessionFactory.getCurrentSession().delete(O);

		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();
	}

	public otpGeneration getByOtp_ID(int Otp_Id) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();

		otpGeneration ogt = (otpGeneration) sessionFactory.getCurrentSession().get(otpGeneration.class, Otp_Id);
		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();
		return ogt;

	}

	public int save(otpGeneration otpgeneration) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		int ogt = (Integer) sessionFactory.getCurrentSession().save(otpgeneration);
		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();
		return ogt;

	}

	public void update(otpGeneration otpgeneration) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		sessionFactory.getCurrentSession().merge(otpgeneration);
		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();

	}

	public int updateOtpgen(String clientid, String tranId) {

		Session session = sessionFactory.openSession();

		Transaction tx = session.beginTransaction();
		Query qry = session.createQuery("update otpGeneration og set og.OTP_STATUS=? where og.STATUS=1 and og.UNIQUE_ID='" + tranId + "'");
		qry.setParameter(0, 1);

		int res = qry.executeUpdate();
		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();

		// Session session = sessionFactory.openSession();
		// Query q = session.createQuery("from otpGeneration where STATUS =
		// :STATUS ");
		// q.setParameter("STATUS", "1");
		// otpGeneration stockTran = (otpGeneration) q.list().get(0);
		// session.update(stockTran);

		return 0;

	}

	public void view(otpGeneration otpgeneration) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		sessionFactory.getCurrentSession().merge(otpgeneration);
		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();

	}

	public List<otpGeneration> getDuplicate_ID(String clientid, String uniqueid) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria query = sessionFactory.getCurrentSession().createCriteria(otpGeneration.class);
		Criterion cn = Restrictions.eq("REQUEST_BY", clientid);
		Criterion cn1 = Restrictions.eq("UNIQUE_ID", uniqueid);
		Criterion cn2 = Restrictions.eq("ENV_TYPE", "PREPROD");
		query.add(cn);
		query.add(cn1);
		query.add(cn2);
		List<otpGeneration> ogt = query.list();

		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();

		return ogt;

	}

	public List<otpGeneration> getaadhaarNumber(String uniqueid, String client_id) {

		Session session = sessionFactory.openSession();
		Transaction tx = session.beginTransaction();
		Criteria query = sessionFactory.getCurrentSession().createCriteria(otpGeneration.class);
		Criterion cn = Restrictions.eq("UNIQUE_ID", uniqueid);
		Criterion cn1 = Restrictions.eq("OTP_STATUS", 0);
		Criterion cn2 = Restrictions.eq("STATUS", "1");
		Criterion cn3 = Restrictions.eq("REQUEST_BY", client_id);
		Criterion cn4 = Restrictions.eq("ENV_TYPE", "PREPROD");
		query.add(cn);
		query.add(cn1);
		query.add(cn2);
		query.add(cn3);
		query.add(cn4);

		List<otpGeneration> ogt = query.list();

		session.flush();
		session.clear();
		tx.commit();
		sessionFactory.close();

		return ogt;

	}

}
