/*
 * 
 */
package com.auth.bean;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

// TODO: Auto-generated Javadoc
/**
 * The Class Personal.
 */
@Entity
@Table(name = "ab_personal_details")
public class Personal {

	/** The id. */
	@Id
	@GeneratedValue
	private int ID;

	/** The name. */
	@Column
	private String NAME;

	/** The dob. */
	@Column
	private String DOB;

	/** The dob type. */
	@Column
	private String DOB_TYPE;

	/** The gender. */
	@Column
	private String GENDER;

	/** The Emial. */
	@Column
	private String EMAIL;

	/** The mobilenumber. */
	@Column
	private String MOBILE_NUMBER;

	/** The ab verification id. */
	@Column
	private int AB_VERIFICATION_ID;

	// @ManyToOne
	// @JoinColumn(name = "AB_VERIFICATION_ID")
	// private Verification verification;

	/**
	 * Instantiates a new personal.
	 */
	public Personal() {
	}

	/**
	 * Instantiates a new personal.
	 *
	 * @param ID
	 *            the id
	 * @param NAME
	 *            the name
	 * @param DOB
	 *            the dob
	 * @param AB_VERIFICATION_ID
	 *            the ab verification id
	 * @param DOB_TYPE
	 *            the dob type
	 * @param GENDER
	 *            the gender
	 */
	public Personal(int ID, String NAME, String DOB, int AB_VERIFICATION_ID, String DOB_TYPE, String GENDER,
			String EMAIL, String MOBILE_NUMBER) {
		
		super();
		this.ID = ID;
		this.NAME = NAME;
		this.DOB = DOB;
		this.DOB_TYPE = DOB_TYPE;
		this.GENDER = GENDER;
		this.AB_VERIFICATION_ID = AB_VERIFICATION_ID;
		this.EMAIL = EMAIL;
		this.MOBILE_NUMBER = MOBILE_NUMBER;
		// this.verification = verification;
		
	}

	/**
	 * Gets the name.
	 *
	 * @return the name
	 */
	public String getNAME() {
		return NAME;
	}

	/**
	 * Sets the name.
	 *
	 * @param nAME
	 *            the new name
	 */
	public void setNAME(String nAME) {
		NAME = nAME;
	}

	/**
	 * Gets the dob.
	 *
	 * @return the dob
	 */
	public String getDOB() {
		return DOB;
	}

	/**
	 * Sets the dob.
	 *
	 * @param dOB
	 *            the new dob
	 */
	public void setDOB(String dOB) {
		DOB = dOB;
	}

	/**
	 * Gets the dob type.
	 *
	 * @return the dob type
	 */
	public String getDOB_TYPE() {
		return DOB_TYPE;
	}

	/**
	 * Sets the dob type.
	 *
	 * @param dOB_TYPE
	 *            the new dob type
	 */
	public void setDOB_TYPE(String dOB_TYPE) {
		DOB_TYPE = dOB_TYPE;
	}

	/**
	 * Gets the gender.
	 *
	 * @return the gender
	 */
	public String getGENDER() {
		return GENDER;
	}

	/**
	 * Sets the gender.
	 *
	 * @param gENDER
	 *            the new gender
	 */
	public void setGENDER(String gENDER) {
		GENDER = gENDER;
	}

	/**
	 * Gets the ab verification id.
	 *
	 * @return the ab verification id
	 */
	public int getAB_VERIFICATION_ID() {
		return AB_VERIFICATION_ID;
	}

	/**
	 * Sets the ab verification id.
	 *
	 * @param aB_VERIFICATION_ID
	 *            the new ab verification id
	 */
	public void setAB_VERIFICATION_ID(int aB_VERIFICATION_ID) {
		AB_VERIFICATION_ID = aB_VERIFICATION_ID;
	}

	public String getEMAIL() {
		return EMAIL;
	}

	public void setEMAIL(String eMAIL) {
		
		EMAIL = eMAIL;
	}

	public String getMOBILE_NUMBER() {
		return MOBILE_NUMBER;
	}

	public void setMOBILE_NUMBER(String mOBILE_NUMBER) {
		MOBILE_NUMBER = mOBILE_NUMBER;
	}

}
