/*
 * 
 */
package com.auth.bean;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

// TODO: Auto-generated Javadoc
/**
 * The Class Residential.
 */
@Entity
@Table(name = "ab_residential_address")
public class Residential {

	/** The id. */
	@Id
	@SequenceGenerator(name = "seq_verification", sequenceName = "seq_verification")
	@GeneratedValue(strategy = GenerationType.AUTO, generator = "seq_verification")

	private int ID;

	/** The care of. */
	@Column
	private String CARE_OF;

	/** The building. */
	@Column
	private String BUILDING;

	/** The street. */
	@Column
	private String STREET;

	/** The landmark. */
	@Column
	private String LANDMARK;

	/** The locality. */
	@Column
	private String LOCALITY;

	/** The village town city. */
	@Column
	private String VILLAGE_TOWN_CITY;

	/** The district. */
	@Column
	private String DISTRICT;

	/** The subdistrict. */
	@Column
	private String SUBDISTRICT;

	/** The state. */
	@Column
	private String STATE;

	/** The pincode. */
	@Column
	private String PINCODE;

	/** The country. */
	@Column
	private String COUNTRY;

	/** The poname. */
	@Column
	private String PONAME;

	/** The fulladdress. */
	@Column
	private String FULLADDRESS;

	/** The ab verification id. */
	@Column
	private int AB_VERIFICATION_ID;

	/**
	 * Instantiates a new residential.
	 */
	public Residential() {
	}

	/**
	 * Instantiates a new residential.
	 *
	 * @param ID
	 *            the id
	 * @param CARE_OF
	 *            the care of
	 * @param AB_VERIFICATION_ID
	 *            the ab verification id
	 * @param BUILDING
	 *            the building
	 * @param STREET
	 *            the street
	 * @param LANDMARK
	 *            the landmark
	 * @param LOCALITY
	 *            the locality
	 * @param VILLAGE_TOWN_CITY
	 *            the village town city
	 * @param DISTRICT
	 *            the district
	 * @param SUBDISTRICT
	 *            the subdistrict
	 * @param STATE
	 *            the state
	 * @param PINCODE
	 *            the pincode
	 * @param COUNTRY
	 *            the country
	 * @param PONAME
	 *            the poname
	 * @param FULLADDRESS
	 *            the fulladdress
	 */
	public Residential(int ID, String CARE_OF, int AB_VERIFICATION_ID, String BUILDING, String STREET, String LANDMARK,
			String LOCALITY, String VILLAGE_TOWN_CITY, String DISTRICT, String SUBDISTRICT, String STATE,
			String PINCODE, String COUNTRY, String PONAME, String FULLADDRESS) {
		super();
		this.ID = ID;
		this.CARE_OF = CARE_OF;
		this.BUILDING = BUILDING;
		this.STREET = STREET;
		this.LANDMARK = LANDMARK;
		this.LOCALITY = LOCALITY;
		this.VILLAGE_TOWN_CITY = VILLAGE_TOWN_CITY;
		this.DISTRICT = DISTRICT;
		this.STATE = STATE;
		this.PINCODE = PINCODE;
		this.COUNTRY = COUNTRY;
		this.AB_VERIFICATION_ID = AB_VERIFICATION_ID;
		this.SUBDISTRICT = SUBDISTRICT;
		this.PONAME = PONAME;
		this.FULLADDRESS = FULLADDRESS;
	}

	/**
	 * Gets the id.
	 *
	 * @return the id
	 */
	public int getID() {
		return ID;
	}

	/**
	 * Sets the id.
	 *
	 * @param iD
	 *            the new id
	 */
	public void setID(int iD) {
		ID = iD;
	}

	/**
	 * Gets the care of.
	 *
	 * @return the care of
	 */
	public String getCARE_OF() {
		return CARE_OF;
	}

	/**
	 * Sets the care of.
	 *
	 * @param cARE_OF
	 *            the new care of
	 */
	public void setCARE_OF(String cARE_OF) {
		CARE_OF = cARE_OF;
	}

	/**
	 * Gets the building.
	 *
	 * @return the building
	 */
	public String getBUILDING() {
		return BUILDING;
	}

	/**
	 * Sets the building.
	 *
	 * @param bUILDING
	 *            the new building
	 */
	public void setBUILDING(String bUILDING) {
		BUILDING = bUILDING;
	}

	/**
	 * Gets the street.
	 *
	 * @return the street
	 */
	public String getSTREET() {
		return STREET;
	}

	/**
	 * Sets the street.
	 *
	 * @param sTREET
	 *            the new street
	 */
	public void setSTREET(String sTREET) {
		STREET = sTREET;
	}

	/**
	 * Gets the landmark.
	 *
	 * @return the landmark
	 */
	public String getLANDMARK() {
		return LANDMARK;
	}

	/**
	 * Sets the landmark.
	 *
	 * @param lANDMARK
	 *            the new landmark
	 */
	public void setLANDMARK(String lANDMARK) {
		LANDMARK = lANDMARK;
	}

	/**
	 * Gets the locality.
	 *
	 * @return the locality
	 */
	public String getLOCALITY() {
		return LOCALITY;
	}

	/**
	 * Sets the locality.
	 *
	 * @param lOCALITY
	 *            the new locality
	 */
	public void setLOCALITY(String lOCALITY) {
		LOCALITY = lOCALITY;
	}

	/**
	 * Gets the village town city.
	 *
	 * @return the village town city
	 */
	public String getVILLAGE_TOWN_CITY() {
		return VILLAGE_TOWN_CITY;
	}

	/**
	 * Sets the village town city.
	 *
	 * @param vILLAGE_TOWN_CITY
	 *            the new village town city
	 */
	public void setVILLAGE_TOWN_CITY(String vILLAGE_TOWN_CITY) {
		VILLAGE_TOWN_CITY = vILLAGE_TOWN_CITY;
	}

	/**
	 * Gets the district.
	 *
	 * @return the district
	 */
	public String getDISTRICT() {
		return DISTRICT;
	}

	/**
	 * Sets the district.
	 *
	 * @param dISTRICT
	 *            the new district
	 */
	public void setDISTRICT(String dISTRICT) {
		DISTRICT = dISTRICT;
	}

	/**
	 * Gets the state.
	 *
	 * @return the state
	 */
	public String getSTATE() {
		return STATE;
	}

	/**
	 * Sets the state.
	 *
	 * @param sTATE
	 *            the new state
	 */
	public void setSTATE(String sTATE) {
		STATE = sTATE;
	}

	/**
	 * Gets the pincode.
	 *
	 * @return the pincode
	 */
	public String getPINCODE() {
		return PINCODE;
	}

	/**
	 * Sets the pincode.
	 *
	 * @param pINCODE
	 *            the new pincode
	 */
	public void setPINCODE(String pINCODE) {
		PINCODE = pINCODE;
	}

	/**
	 * Gets the country.
	 *
	 * @return the country
	 */
	public String getCOUNTRY() {
		return COUNTRY;
	}

	/**
	 * Sets the country.
	 *
	 * @param cOUNTRY
	 *            the new country
	 */
	public void setCOUNTRY(String cOUNTRY) {
		COUNTRY = cOUNTRY;
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

	/**
	 * Gets the subdistrict.
	 *
	 * @return the subdistrict
	 */
	public String getSUBDISTRICT() {
		return SUBDISTRICT;
	}

	/**
	 * Sets the subdistrict.
	 *
	 * @param sUBDISTRICT
	 *            the new subdistrict
	 */
	public void setSUBDISTRICT(String sUBDISTRICT) {
		SUBDISTRICT = sUBDISTRICT;
	}

	/**
	 * Gets the poname.
	 *
	 * @return the poname
	 */
	public String getPONAME() {
		return PONAME;
	}

	/**
	 * Sets the poname.
	 *
	 * @param pONAME
	 *            the new poname
	 */
	public void setPONAME(String pONAME) {
		PONAME = pONAME;
	}

	/**
	 * Gets the fulladdress.
	 *
	 * @return the fulladdress
	 */
	public String getFULLADDRESS() {
		return FULLADDRESS;
	}

	/**
	 * Sets the fulladdress.
	 *
	 * @param fULLADDRESS
	 *            the new fulladdress
	 */
	public void setFULLADDRESS(String fULLADDRESS) {
		FULLADDRESS = fULLADDRESS;
	}

}
