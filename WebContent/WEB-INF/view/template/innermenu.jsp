<div class="menuHeader">
           <div class="authLogo">
            
            
           <span> 
           
           <img style="float: left; padding-top: 1px; padding-left: 2px; background-color: rgb(255, 255, 255); margin-left: 3px; margin-top: 3px; height: 72px; border-radius: 3px;" src="${pageContext.request.contextPath}/resources/images/logo.png">
             
          </span>
          
          
          <div class="head_menu_right">
      
              <% if(session.getAttribute("user_login_name") != null) { %>
               
                         <span  style="margin-top: 10px;margin-right: 91px;font-weight: bold;font-size: 15px;"> You Are Logged In As <%= session.getAttribute("user_login_name")%> </span>
                <% } %>
      
            
            <div class="inner_ineer_menu">
                 
                  <div class="inner_inner_menu_left">
                    <span>
                       <a href="<c:url value="/cpassword.html"/>">Change Password</a>
                    </span>
                    
                  </div>
                 
                  <span style="float: left;"> &#124;</span>
                  <div class="inner_inner_menu_right">
                   <span>
                   
                      <a href="<c:url value="/logout.html"/>">Logout</a>
                   </span>
                  
                  </div>
                 
            
            </div>
          </div>  
            
            </div>
             <!--Menu Code -->
          
            <div class="mainMenu">
                <ul style="float: left;">
                 
                  <li id="insideLi">
                     <a href="<c:url value="/home.html"/>">Demo Auth</a>
                  </li>
                  
                   <li id="insideLi">
                     <a href="<c:url value="/bio.html"/>">Bio Auth</a>
                  </li>
                   <li id="insideLi">
                     <a href="<c:url value="/otp.html"/>">Otp Auth</a>
                  </li>
                  
                 <% if(session.getAttribute("user_login_name").equals("authbridge")) { %>
                       
                        <li id="insideLi">
                               <a href="<c:url value="/aadhaarattendence.html"/>">Aadhaar Attendence</a>
                         </li>    
                  <% } %>
                  
                <!--     <li id="insideLi" style="width:150px;">
                     <a href="<c:url value="/ekyc.html"/>">Ekyc</a>
                  </li>
                   <li id="insideLi" style="width:150px;">
                     <a href="<c:url value="/esign.html"/>">Esign</a>
                  </li>-->
                 <!--  
                 <li id="insideLi">
                     <a href="<c:url value="/MOU.html"/>">Mobile Update</a>
                  </li>
                
                </ul>
                --> 
              
            </div>
            
         <!-- End Menu Code -->  
         </div>
         
         
         <script type="text/javascript">
     $(function (){

    $('.mainMenu ul li a').each(function(){
        var path = window.location.href;
        var current = path.substring(path.lastIndexOf('/')+1);
        var url = $(this).attr('href').substring($(this).attr('href').lastIndexOf('/')+1);
        
        
        if(url == current){
        	
            $(this).addClass('activemenu');
        };
    });         
});

</script>