/*
 * 
 */
package com.auth.util;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;

import com.auth.util.Log;

// TODO: Auto-generated Javadoc
/**
 * The Class AUAProperties.
 */
public class AUAProperties {

	/** The log path. */
	private static String logPath;
  
	
	
	
	/**
	 * Load.
	 *
	 * @param str the str
	 */
	public static void load(String str)
	{
	    Properties properties = new Properties();
	    try
	    {
	      
	    	try
	    	{
	    		
	    		
	    		ClassLoader classloader = Thread.currentThread().getContextClassLoader();
	    		properties.load(new FileInputStream(new File(classloader.getResource("aua.properties").getFile())));
	    	   
	    		if (properties.getProperty("logPath") != null) {
					logPath=properties.getProperty("logPath").toString();
				}
	    	
	    	}
	    	catch(Exception e)
	    	{
	    		System.out.println(e);
	    	}
	  
            
	    }
	    catch (Exception e)
	    {
	    	e.printStackTrace();
	    	System.out.println("Unable to load properties"+e);
	    }
	}




	/**
	 * Gets the log path.
	 *
	 * @return the log path
	 */
	public static String getLogPath() {
		return logPath;
	}




	/**
	 * Sets the log path.
	 *
	 * @param logPath the new log path
	 */
	public static void setLogPath(String logPath) {
		AUAProperties.logPath = logPath;
	}
	
	
}
