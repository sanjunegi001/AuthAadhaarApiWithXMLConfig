/*
 * 
 */
package com.auth.controller;

import java.sql.SQLException;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.auth.domain.User;
import com.auth.dao.UserLoginDAO;
import com.auth.domain.PassUser;

// TODO: Auto-generated Javadoc
/**
 * The Class CpasswordController.
 */
@Controller
public class CpasswordController {

	@Autowired
    private UserLoginDAO userLogindao;
	
	/**
	 * Cpassword.
	 *
	 * @param user the user
	 * @param session the session
	 * @return the model and view
	 * @throws Exception the exception
	 */
	@RequestMapping(value="/cpassword",method = RequestMethod.GET)
	public ModelAndView cpassword(@ModelAttribute("user") User user,HttpSession session) throws Exception
	{
		
		int access= userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(),session);
		
		
		 if(session.getAttribute("user_login_name")!=null && access==1)
		 {
			 return new ModelAndView("cpassword");
		 }
		 else
		 {
			 return new ModelAndView("redirect:/login.html");
			 
		 } 
		 
	}
	
	
	/**
	 * Inprocesschangepass.
	 *
	 * @param passuser the passuser
	 * @param model the model
	 * @param session the session
	 * @return the model and view
	 * @throws Exception the exception
	 */
	@RequestMapping(value="/Inprocesschangepass",method= RequestMethod.POST)
	public ModelAndView Inprocesschangepass(@ModelAttribute("passuser") PassUser passuser,Model model,HttpSession session) throws Exception
	{
		
		
		int access= userLogindao.isAcessDetails(session.getAttribute("user_login_name").toString(),session);
		
		 if(session.getAttribute("user_login_name")!=null && access==1)
		 {
			 
		    String oldpassword = passuser.getOldpassword().trim();
		    String Newpassword = passuser.getNewpassword().trim();
		    String Confirmpassword = passuser.getConfirmpass().trim();
		    
		   
		    
		    try {
		    	
		    	if(passuser.getOldpassword().trim() == "")
				{
					
					model.addAttribute("error","OldPassword Is Required!");
					return new ModelAndView("cpassword");				
			    }
		    	
		    	else if(passuser.getNewpassword().trim() == "")
				{
					
					model.addAttribute("error","NewPassword Is Required!");
					return new ModelAndView("cpassword");				
			    }
		    	
		    	else if(passuser.getConfirmpass().trim() == "")
				{
					
					model.addAttribute("error","ConfirmPassword Is Required!");
					return new ModelAndView("cpassword");				
			    }
		    	
		    	else if(Newpassword.contains(Confirmpassword))
		    	{
		    		
		    		int ischangepasswors =userLogindao.isPassChaange(oldpassword, Newpassword, session.getAttribute("user_login_name").toString());
					  if(ischangepasswors ==1)
					  {
						  
						    model.addAttribute("success","Password Changed Successfully");
							return new ModelAndView("cpassword");
					  }
					  else
					  {
						    model.addAttribute("error","Old Password is Not Matched");
							return new ModelAndView("cpassword");
					  }
		    		
		    	}
		    	
		    	else
		    	{
		    		model.addAttribute("error","New password and Confirm password Are Not Matched! ");
					return new ModelAndView("cpassword");
		    	}
		    	
		    	
			
				
				
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		    
		
			 
			 
			 return new ModelAndView("cpassword");
		 }
		 else
		 {
			 return new ModelAndView("redirect:/login.html");
			 
		 } 
		 
	}
		
	
	
}
