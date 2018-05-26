/*
 * 
 */
package com.auth.util;

import java.io.IOException;

import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

// TODO: Auto-generated Javadoc
/**
 * The Class Log.
 */
public class Log {

	/** The subaua. */
	public static Logger aua = Logger.getLogger("AUA");

	static {
		FileAppender appender1 = null;

		//PREAUAProperties.load();
		String log_path = PREAUAProperties.getLogPath();

		try {
			appender1 = new DailyRollingFileAppender(new PatternLayout("%d{dd-MM-yyyy HH:mm:ss} %C %L %-5p: %m%n"),
					log_path, "'.'dd-MM-yyyy");
		} catch (IOException e) {
			e.printStackTrace();
		}
		aua.setLevel(Level.DEBUG);
		aua.addAppender(appender1);
	}

}
