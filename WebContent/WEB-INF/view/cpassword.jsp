<%@ include file="template/header.jsp" %>

<script type="text/javascript">

  function checkForm(form)
  {
   
	  var coldpassword = document.getElementById('oldpassword').value;
	  var cnewpassword = document.getElementById('newpassword').value;
	  var cconfirmpass = document.getElementById('confirmpass').value;
	  
	  if(coldpassword==null || coldpassword=="")
		  {
		     alert("Error: Old Password Is Required");
		     return false;
		  }
	  if(cnewpassword == null || cnewpassword =="")
		  {
		      alert("Error: New Password Is Required");
			  return false;
		  }
	  
	  if(cconfirmpass == null || cconfirmpass=="")
		  {
		     alert("Error: Confirm Password Is Required");
		     return false;
		  }

    if(cnewpassword == cconfirmpass) {
    	
      if(cnewpassword.length < 6) {
        alert("Error: Password must contain at least six characters!");
        
        return false;
      }
     
      var re = /[0-9]/;
      if(!re.test(cnewpassword)) {
        alert("Error: password must contain at least one number (0-9)!");
        
        return false;
      }
      var re = /[a-z]/;
      if(!re.test(cnewpassword)) {
        alert("Error: password must contain at least one lowercase letter (a-z)!");
        
        return false;
      }
      var re = /[A-Z]/;
      if(!re.test(cnewpassword)) {
        alert("Error: password must contain at least one uppercase letter (A-Z)!");
        return false;
      }
    } else {
      alert("Error: New Password and confirmed password not matched!");
      
      return false;
    }

   
    return true;
  }

</script>


     <div class="mainDiv">
     
     
         <div class="innermainDiv">
         
         <%@ include file="template/innermenu.jsp" %>
         
         
         <div class="mainForm1">
         
            <br>
            <br>
         
          <c:url var="passchangeForm" value="Inprocesschangepass.html" />
             
          
             <form:form id="passchangeForm" name="bioauthForm"  modelAttribute="passuser" action="${passchangeForm}" class="chform" onsubmit="return checkForm(this);">
             
                 <span class="heading-changepassword">Change account password</span>
                 
                  <span  style="float:left;padding-bottom: 17px; width: 500px;color: #148813;font-weight: bold;">
                    <span style="text-align:center"> ${success}</span>
                  </span>
                
                 
                 <span  style="float:left;padding-bottom: 17px; width: 500px;color: #f73030;font-weight: bold;">
                    <span style="text-align:center"> ${error}</span>
                 </span>
             
             
                 <div class="mainaadharForm">
                 
                     <div class="form-group1">
                        <label class="col-md-2 control-label">Old Password</label>
                         <div class="col-md-20">
                                    <input type="password" id="oldpassword" name="oldpassword" class="form-control" placeholder="Old Password" />
                                    
                         </div>
                     </div>
                     
                     
                     <div class="form-group1">
                        <label class="col-md-2 control-label">New Password</label>
                         <div class="col-md-21">
                                    <input type="password" id="newpassword" name="newpassword" class="form-control" placeholder="New Password" />
                                    
                         </div>
                     </div>
                     
                     
                     <div class="form-group1">
                        <label class="col-md-2 control-label">Confirm New Password</label>
                         <div class="col-md-22">
                                    <input type="password" id="confirmpass" name="confirmpass" class="form-control" placeholder="Confirm New Password" />
                                    
                         </div>
                     </div>
                    
                     <input type="hidden" id="hdnSession" value="<%= session.getAttribute("user_login_name") %>" />
                      
                    
                  
                   
             
                     
                    <div class="form-group">
                        <div class="col-md-offset-2 col-md-11">
                        
                        <input type="submit" value="Save"  class="btn btn-default1" id="inneraction_buttion_auth_login">
                     
                        </div>
                   </div>
                 
                 
                 </div>
             
             
             
             </form:form>
         
         
         
         
         </div>  
         
         
         
         </div>
     
     
    <%@ include file="template/footer.jsp" %>