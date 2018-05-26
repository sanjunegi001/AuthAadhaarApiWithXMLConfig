/*
 * 
 */
package com.auth.bean;

import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

// TODO: Auto-generated Javadoc
/**
 * The Class Verification.
 */
@Entity
@Table(name = "ab_verification_details")
public class Verification {

	/** The id. */
	@Id
	@SequenceGenerator(name = "seq_verification", sequenceName = "seq_verification")
	@GeneratedValue(strategy = GenerationType.AUTO, generator = "seq_verification")

	private int ID;

	/** The uid. */
	@Column
	private Long UID;

	/** The status. */
	@Column
	private int STATUS;

	/** The status description. */
	@Column
	private String STATUS_DESCRIPTION;

	/** The reference number. */
	@Column
	private String REFERENCE_NUMBER;

	/** The requested by. */
	@Column
	private String REQUESTED_BY;

	/** The transaction id. */
	@Column
	private String TRANSACTION_ID;

	/** The error code. */
	@Column
	private String ERROR_CODE;

	/** The message. */
	@Column
	private String MESSAGE;

	/** The bfd finger match. */
	@Column
	private String BFD_FINGER_MATCH;

	/** The bfd finger rank. */
	@Column
	private int BFD_FINGER_RANK;

	/** The auth type. */
	@Column
	private String AUTH_TYPE;

	/** The aua code. */
	@Column
	private String AUA_CODE;

	/** The sub aua code. */
	@Column
	private String SUB_AUA_CODE;

	/** The udc code. */
	@Column
	private String UDC_CODE;

	/** The fdc code. */
	@Column
	private String FDC_CODE;

	/** The api name. */
	@Column
	private String API_NAME;

	/** The server response on. */
	@Column
	private String SERVER_RESPONSE_ON;

	/** The request on. */
	@Column
	@Temporal(TemporalType.TIMESTAMP)
	private Date REQUEST_ON;

	/** The response on. */

	@Column
	@Temporal(TemporalType.TIMESTAMP)
	private Date RESPONSE_ON;

	/** The country. */
	@Column
	private String COUNTRY;

	/** The city. */
	@Column
	private String CITY;

	/** The pincode. */
	@Column
	private int PINCODE;

	/** The ipaddress. */
	@Column
	private String IPADDRESS;

	/** The conscent. */
	@Column
	private int CONSENT;

	/** The envtype. */
	@Column
	private String ENV_TYPE;

	/** The envtype. */
	@Column
	private String ASA_NAME;

	/** The Contact. */
	@Transient
	private List<String> Contact;

	/** The Personal. */
	@Transient
	private List<String> Personal;

	/** The Residential. */
	@Transient
	private List<String> Residential;

	/**
	 * Instantiates a new verification.
	 */
	public Verification() {

	}

	/**
	 * Instantiates a new verification.
	 *
	 * @param ID
	 *            the id
	 * @param UID
	 *            the uid
	 * @param STATUS
	 *            the status
	 * @param STATUS_DESCRIPTION
	 *            the status description
	 * @param REFERENCE_NUMBER
	 *            the reference number
	 * @param REQUESTED_BY
	 *            the requested by
	 * @param TRANSACTION_ID
	 *            the transaction id
	 * @param ERROR_CODE
	 *            the error code
	 * @param MESSAGE
	 *            the message
	 * @param BFD_FINGER_MATCH
	 *            the bfd finger match
	 * @param BFD_FINGER_RANK
	 *            the bfd finger rank
	 * @param AUTH_TYPE
	 *            the auth type
	 * @param AUA_CODE
	 *            the aua code
	 * @param SUB_AUA_CODE
	 *            the sub aua code
	 * @param UDC_CODE
	 *            the udc code
	 * @param FDC_CODE
	 *            the fdc code
	 * @param API_NAME
	 *            the api name
	 * @param SERVER_RESPONSE_ON
	 *            the server response on
	 * @param REQUEST_ON
	 *            the request on
	 * @param RESPONSE_ON
	 *            the response on
	 * @param COUNTRY
	 *            the country
	 * @param CITY
	 *            the city
	 * @param PINCODE
	 *            the pincode
	 * @param IPADDRESS
	 *            the ipaddress
	 */
	public Verification(int ID, int UID, int STATUS, String STATUS_DESCRIPTION, String UIDAI_CODE, String REQUESTED_BY, String TRANSACTION_ID, String ERROR_CODE, String MESSAGE, String BFD_FINGER_MATCH, int BFD_FINGER_RANK, String AUTH_TYPE, String AUA_CODE, String SUB_AUA_CODE, String UDC_CODE, String FDC_CODE, String API_NAME, String SERVER_RESPONSE_ON, Date REQUEST_ON, Date RESPONSE_ON, String COUNTRY, String CITY, int PINCODE, String IPADDRESS, int CONSENT, String ENV_TYPE, String ASA_NAME) {
		super();
		this.ID = ID;
		this.STATUS = STATUS;
		this.STATUS_DESCRIPTION = STATUS_DESCRIPTION;
		this.REFERENCE_NUMBER = REFERENCE_NUMBER;
		this.REQUESTED_BY = REQUESTED_BY;
		this.TRANSACTION_ID = TRANSACTION_ID;
		this.ERROR_CODE = ERROR_CODE;
		this.MESSAGE = MESSAGE;
		this.BFD_FINGER_MATCH = BFD_FINGER_MATCH;
		this.BFD_FINGER_RANK = BFD_FINGER_RANK;
		this.AUTH_TYPE = AUTH_TYPE;
		this.AUA_CODE = AUA_CODE;
		this.SUB_AUA_CODE = SUB_AUA_CODE;
		this.UDC_CODE = UDC_CODE;
		this.FDC_CODE = FDC_CODE;
		this.API_NAME = API_NAME;
		this.SERVER_RESPONSE_ON = SERVER_RESPONSE_ON;
		this.REQUEST_ON = REQUEST_ON;
		this.RESPONSE_ON = RESPONSE_ON;
		this.COUNTRY = COUNTRY;
		this.CITY = CITY;
		this.PINCODE = PINCODE;
		this.IPADDRESS = IPADDRESS;
		this.CONSENT = CONSENT;
		this.ENV_TYPE = ENV_TYPE;
		this.ASA_NAME = ASA_NAME;

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
	 * Gets the uid.
	 *
	 * @return the uid
	 */
	public Long getUID() {
		return UID;
	}

	/**
	 * Sets the uid.
	 *
	 * @param uID
	 *            the new uid
	 */
	public void setUID(Long uID) {
		UID = uID;
	}

	/**
	 * Gets the status.
	 *
	 * @return the status
	 */
	public int getSTATUS() {
		return STATUS;
	}

	/**
	 * Sets the status.
	 *
	 * @param sTATUS
	 *            the new status
	 */
	public void setSTATUS(int sTATUS) {
		STATUS = sTATUS;
	}

	/**
	 * Gets the status description.
	 *
	 * @return the status description
	 */
	public String getSTATUS_DESCRIPTION() {
		return STATUS_DESCRIPTION;
	}

	/**
	 * Sets the status description.
	 *
	 * @param sTATUS_DESCRIPTION
	 *            the new status description
	 */
	public void setSTATUS_DESCRIPTION(String sTATUS_DESCRIPTION) {
		STATUS_DESCRIPTION = sTATUS_DESCRIPTION;
	}

	/**
	 * Gets the reference number.
	 *
	 * @return the reference number
	 */
	public String getREFERENCE_NUMBER() {
		return REFERENCE_NUMBER;
	}

	public void setREFERENCE_NUMBER(String rEFERENCE_NUMBER) {
		REFERENCE_NUMBER = rEFERENCE_NUMBER;
	}

	/**
	 * Gets the requested by.
	 *
	 * @return the requested by
	 */
	public String getREQUESTED_BY() {
		return REQUESTED_BY;
	}

	/**
	 * Sets the requested by.
	 *
	 * @param rEQUESTED_BY
	 *            the new requested by
	 */
	public void setREQUESTED_BY(String rEQUESTED_BY) {
		REQUESTED_BY = rEQUESTED_BY;
	}

	/**
	 * Gets the transaction id.
	 *
	 * @return the transaction id
	 */
	public String getTRANSACTION_ID() {
		return TRANSACTION_ID;
	}

	/**
	 * Sets the transaction id.
	 *
	 * @param tRANSACTION_ID
	 *            the new transaction id
	 */
	public void setTRANSACTION_ID(String tRANSACTION_ID) {
		TRANSACTION_ID = tRANSACTION_ID;
	}

	/**
	 * Gets the error code.
	 *
	 * @return the error code
	 */
	public String getERROR_CODE() {
		return ERROR_CODE;
	}

	/**
	 * Sets the error code.
	 *
	 * @param eRROR_CODE
	 *            the new error code
	 */
	public void setERROR_CODE(String eRROR_CODE) {
		ERROR_CODE = eRROR_CODE;
	}

	/**
	 * Gets the message.
	 *
	 * @return the message
	 */
	public String getMESSAGE() {
		return MESSAGE;
	}

	/**
	 * Sets the message.
	 *
	 * @param mESSAGE
	 *            the new message
	 */
	public void setMESSAGE(String mESSAGE) {
		MESSAGE = mESSAGE;
	}

	/**
	 * Gets the bfd finger match.
	 *
	 * @return the bfd finger match
	 */
	public String getBFD_FINGER_MATCH() {
		return BFD_FINGER_MATCH;
	}

	/**
	 * Sets the bfd finger match.
	 *
	 * @param bFD_FINGER_MATCH
	 *            the new bfd finger match
	 */
	public void setBFD_FINGER_MATCH(String bFD_FINGER_MATCH) {
		BFD_FINGER_MATCH = bFD_FINGER_MATCH;
	}

	/**
	 * Gets the bfd finger rank.
	 *
	 * @return the bfd finger rank
	 */
	public int getBFD_FINGER_RANK() {
		return BFD_FINGER_RANK;
	}

	/**
	 * Sets the bfd finger rank.
	 *
	 * @param bFD_FINGER_RANK
	 *            the new bfd finger rank
	 */
	public void setBFD_FINGER_RANK(int bFD_FINGER_RANK) {
		BFD_FINGER_RANK = bFD_FINGER_RANK;
	}

	/**
	 * Gets the auth type.
	 *
	 * @return the auth type
	 */
	public String getAUTH_TYPE() {
		return AUTH_TYPE;
	}

	/**
	 * Sets the auth type.
	 *
	 * @param aUTH_TYPE
	 *            the new auth type
	 */
	public void setAUTH_TYPE(String aUTH_TYPE) {
		AUTH_TYPE = aUTH_TYPE;
	}

	/**
	 * Gets the aua code.
	 *
	 * @return the aua code
	 */
	public String getAUA_CODE() {
		return AUA_CODE;
	}

	/**
	 * Sets the aua code.
	 *
	 * @param aUA_CODE
	 *            the new aua code
	 */
	public void setAUA_CODE(String aUA_CODE) {
		AUA_CODE = aUA_CODE;
	}

	/**
	 * Gets the contact.
	 *
	 * @return the contact
	 */
	public List<String> getContact() {
		return Contact;
	}

	/**
	 * Sets the contact.
	 *
	 * @param contact
	 *            the new contact
	 */
	public void setContact(List<String> contact) {
		Contact = contact;
	}

	/**
	 * Gets the personal.
	 *
	 * @return the personal
	 */
	public List<String> getPersonal() {
		return Personal;
	}

	/**
	 * Sets the personal.
	 *
	 * @param personal
	 *            the new personal
	 */
	public void setPersonal(List<String> personal) {
		Personal = personal;
	}

	/**
	 * Gets the residential.
	 *
	 * @return the residential
	 */
	public List<String> getResidential() {
		return Residential;
	}

	/**
	 * Sets the residential.
	 *
	 * @param residential
	 *            the new residential
	 */
	public void setResidential(List<String> residential) {
		Residential = residential;
	}

	/**
	 * Gets the sub aua code.
	 *
	 * @return the sub aua code
	 */
	public String getSUB_AUA_CODE() {
		return SUB_AUA_CODE;
	}

	/**
	 * Sets the sub aua code.
	 *
	 * @param sUB_AUA_CODE
	 *            the new sub aua code
	 */
	public void setSUB_AUA_CODE(String sUB_AUA_CODE) {
		SUB_AUA_CODE = sUB_AUA_CODE;
	}

	/**
	 * Gets the udc code.
	 *
	 * @return the udc code
	 */
	public String getUDC_CODE() {
		return UDC_CODE;
	}

	/**
	 * Sets the udc code.
	 *
	 * @param uDC_CODE
	 *            the new udc code
	 */
	public void setUDC_CODE(String uDC_CODE) {
		UDC_CODE = uDC_CODE;
	}

	/**
	 * Gets the fdc code.
	 *
	 * @return the fdc code
	 */
	public String getFDC_CODE() {
		return FDC_CODE;
	}

	/**
	 * Sets the fdc code.
	 *
	 * @param fDC_CODE
	 *            the new fdc code
	 */
	public void setFDC_CODE(String fDC_CODE) {
		FDC_CODE = fDC_CODE;
	}

	/**
	 * Gets the api name.
	 *
	 * @return the api name
	 */
	public String getAPI_NAME() {
		return API_NAME;
	}

	/**
	 * Sets the api name.
	 *
	 * @param aPI_NAME
	 *            the new api name
	 */
	public void setAPI_NAME(String aPI_NAME) {
		API_NAME = aPI_NAME;
	}

	/**
	 * Gets the server response on.
	 *
	 * @return the server response on
	 */
	public String getSERVER_RESPONSE_ON() {
		return SERVER_RESPONSE_ON;
	}

	/**
	 * Sets the server response on.
	 *
	 * @param sERVER_RESPONSE_ON
	 *            the new server response on
	 */
	public void setSERVER_RESPONSE_ON(String sERVER_RESPONSE_ON) {
		SERVER_RESPONSE_ON = sERVER_RESPONSE_ON;
	}

	/**
	 * Gets the request on.
	 *
	 * @return the request on
	 */
	public Date getREQUEST_ON() {
		return REQUEST_ON;
	}

	/**
	 * Sets the request on.
	 *
	 * @param rEQUEST_ON
	 *            the new request on
	 */
	public void setREQUEST_ON(Date rEQUEST_ON) {
		REQUEST_ON = rEQUEST_ON;
	}

	/**
	 * Gets the response on.
	 *
	 * @return the response on
	 */
	public Date getRESPONSE_ON() {
		return RESPONSE_ON;
	}

	/**
	 * Sets the response on.
	 *
	 * @param rESPONSE_ON
	 *            the new response on
	 */
	public void setRESPONSE_ON(Date rESPONSE_ON) {
		RESPONSE_ON = rESPONSE_ON;
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
	 * Gets the city.
	 *
	 * @return the city
	 */
	public String getCITY() {
		return CITY;
	}

	/**
	 * Sets the city.
	 *
	 * @param cITY
	 *            the new city
	 */
	public void setCITY(String cITY) {
		CITY = cITY;
	}

	/**
	 * Gets the pincode.
	 *
	 * @return the pincode
	 */
	public int getPINCODE() {
		return PINCODE;
	}

	/**
	 * Sets the pincode.
	 *
	 * @param pINCODE
	 *            the new pincode
	 */
	public void setPINCODE(int pINCODE) {
		PINCODE = pINCODE;
	}

	/**
	 * Gets the ipaddress.
	 *
	 * @return the ipaddress
	 */
	public String getIPADDRESS() {
		return IPADDRESS;
	}

	/**
	 * Sets the ipaddress.
	 *
	 * @param iPADDRESS
	 *            the new ipaddress
	 */
	public void setIPADDRESS(String iPADDRESS) {
		IPADDRESS = iPADDRESS;
	}

	/**
	 * Gets the conscent.
	 *
	 * @return the conscent
	 */
	public int getCONSENT() {
		return CONSENT;
	}

	/**
	 * Sets the conscent.
	 *
	 * @return the conscent
	 */
	public void setCONSENT(int cONSENT) {
		CONSENT = cONSENT;
	}

	/**
	 * Gets the envtype.
	 *
	 * @return the envtype
	 */
	public String getENV_TYPE() {
		return ENV_TYPE;
	}

	/**
	 * Sets the envtype.
	 *
	 * @return the envtype
	 */
	public void setENV_TYPE(String eNV_TYPE) {
		ENV_TYPE = eNV_TYPE;
	}

	public String getASA_NAME() {
		return ASA_NAME;
	}

	public void setASA_NAME(String aSA_NAME) {
		ASA_NAME = aSA_NAME;
	}

}
