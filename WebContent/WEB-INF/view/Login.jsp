<%@ include file="template/loginheader.jsp" %>
  <div class="logininnermainDiv"> 
 
 
 
      <div class="row_left">
         <div class="inner-left-corner">
            
             <div id="image-content" style="margin-top: 8px;float: left;margin-left: 128px;">
             
             <img id="loader" src="<c:url value="/resources/images/aadhaar-logo.png" />" style="width: 445px;"/>
             </div>
             
             <div id="content" style="float: left;text-align: center;">
             
                <p style="color: #212121;font-size: 15px;font-weight: 300;line-height: 1.5;margin-top: 16px;width: 648px;text-align: justify;margin-left: 27px;">
                  
                  <span style="font-weight: bold;">Gateway to AUTHBRIDGE Network</span> 
                  
                  <BR><BR>
                  
                  It is a secure aadhaar authentication system for demographic,biometric and otp.Enter Your username and password here to autenticate your log-in and enjoy the aadhaar authentication services.
                  
                </p>
              
             </div>
         
       
         </div>    
    </div>
 
 
 
 
 
 
 
   <div class="row"> 
    
 
     
     
       <div class="mainFormlogin">
       
         <span class="loginspan" ></span>
  
      
           <c:if test="${exerror ==1}">
                <script>
                   alert('Your Password Is Expired');
                   window.location = 'authpasschange.html';
                </script>
                
             </c:if>
                <%
           
                if (request.getParameter("succmessage") != null) {%>
                	 <p style="color: #68a26d;font-weight: bold;"><%= request.getParameter("succmessage") %></p>
                <% } %>
       
       
       <p  style="color: #f73030;font-weight: bold;">${error}</p>
       
       
       
          <h1 class="login-heading">Login</h1>
         
              
           
             
           
           <c:url var="loginForm" value="processLogin.html" />
           <form:form id="loginForm" name="myloginform" modelAttribute="loginuser" action="${loginForm}">
           
             <div class="mainaadharForm">
             
                  <div id="aadharnumber">
                          <form:label path="username" id="username">User Name</form:label>
                          <input type="text" name="username" id="labelaadhar_input"></input>
                  </div>
                  
                   <div id="aadharnumber">
                          <form:label path="password">Password</form:label>
                          <input type="password" name="password" id="labelaadhar_input" style="margin-left: 9px;"></input>
                   </div>
                   
                   
                     <div id="aadharnumber">
                       
                     
                         <span style="font-weight: bold;float: left;margin-left: 1px;">Captcha</span>
                         <span style="float: left;margin-left: 12px;margin-top: -13px;">
                         
                             <img id="captcha_id" name="imgCaptcha" src="captcha.jpg" style="float:left;">
                         
                              <a href="javascript:;" title="change captcha text" onclick="document.getElementById('captcha_id').src = 'captcha.jpg?' + Math.random();  return false" style="float:left;margin-left: 7px;padding-top: 12px;">
							    <img src="resources/images/refresh.png" />
						      </a>
                         
                         </span>
                        
                     </div>
                     
                     <div id="aadharnumber">
                          <form:label path="captcha" style="margin-left: 47px;">Enter above Image text#</form:label>
                          
                          <input type="text" name="captcha" id="labelaadhar_input" style="margin-left: 63px;"></input>
                      </div>
                     
                     
                   
                    <div class="action_buttion1" style="margin-right: 25px;">
                   
                          <div class="action_buttion_auth_login">
                            <input type="submit" value="Login" id="inneraction_buttion_auth_login">
                          </div>
                     
                   </div>
             
             
             </div>
           
           </form:form>   
       
       </div>
       
     
    </div>   
       
       
    
    </div>
 
 <%@ include file="template/loginfooter.jsp" %>
 