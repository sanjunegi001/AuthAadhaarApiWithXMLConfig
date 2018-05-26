package com.auth.bean;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "ab_device_details")
public class deviceDetails {

	@Id
	@GeneratedValue
	private int ID;

	@Column
	private String SERIALNUMBER;

	@Column
	private String UDC;
	@Column
	private String MCNAME;
	@Column
	private String CREATEDON;
	@Column
	private String STATUS;
	@Column
	private String CLIENTID;

	/**
	 * Instantiates a new deviceDetails.
	 */
	public deviceDetails() {
	}

	public deviceDetails(int ID, String SERIALNUMBER, String UDC, String MCNAME, String CREATEDON, String STATUS, String CLIENTID) {

		super();
		this.ID = ID;
		this.SERIALNUMBER = SERIALNUMBER;
		this.UDC = UDC;
		this.MCNAME = MCNAME;
		this.CREATEDON = CREATEDON;
		this.STATUS = STATUS;
		this.CLIENTID = CLIENTID;

	}

	public String getSERIALNUMBER() {
		return SERIALNUMBER;
	}

	public void setSERIALNUMBER(String sERIALNUMBER) {
		SERIALNUMBER = sERIALNUMBER;
	}

	public String getUDC() {
		return UDC;
	}

	public void setUDC(String uDC) {
		UDC = uDC;
	}

	public String getMCNAME() {
		return MCNAME;
	}

	public void setMCNAME(String mCNAME) {
		MCNAME = mCNAME;
	}

	public String getCREATEDON() {
		return CREATEDON;
	}

	public void setCREATEDON(String cREATEDON) {
		CREATEDON = cREATEDON;
	}

	public String getSTATUS() {
		return STATUS;
	}

	public void setSTATUS(String sTATUS) {
		STATUS = sTATUS;
	}

	public String getCLIENTID() {
		return CLIENTID;
	}

	public void setCLIENTID(String cLIENTID) {
		CLIENTID = cLIENTID;
	}

}
