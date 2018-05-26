/*
 * 
 */
package com.auth.controller;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.auth.domain.Loginuser;

// TODO: Auto-generated Javadoc
/**
 * The Class LogoutController.
 */
@Controller
public class LogoutController {

	/**
	 * Home.
	 *
	 * @param loginuser
	 *            the loginuser
	 * @param model
	 *            the model
	 * @param request
	 *            the request
	 * @param session
	 *            the session
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@RequestMapping(value = "/logout", method = { RequestMethod.GET, RequestMethod.POST })
	public String Home(@ModelAttribute("loginuser") Loginuser loginuser, Model model, HttpServletRequest request,
			HttpSession session) throws IOException {

		Date startTime = null;
		Calendar c1 = Calendar.getInstance();
		startTime = c1.getTime();

		Date connectionStartTime = null;
		String logMsg = "\n-";
		BufferedWriter out = null;
		BufferedWriter out1 = null;
		FileWriter fstream = null;
		FileWriter fstream1 = null;
		Calendar c = Calendar.getInstance();
		long nonce = c.getTimeInMillis();

		ClassLoader classLoader = getClass().getClassLoader();
		fstream = new FileWriter(classLoader.getResource("log-file.txt").getFile(), true);
		out = new BufferedWriter(fstream);

		HttpSession newsession = request.getSession(false);
		if (newsession != null) {

			logMsg += "::Logout: User  " + session.getAttribute("user_login_name") + "::Program end Time:" + startTime
					+ "::Logout TimeinMilisecond= " + nonce;
			out.write(logMsg);
			out.close();

			newsession.invalidate();

		}

		model.addAttribute("succmessage", "You Are Successfully Logout");

		return "redirect:/login.html";
	}

}
