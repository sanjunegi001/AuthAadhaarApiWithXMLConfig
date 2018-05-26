<%@ include file="template/header.jsp" %>



<!-- BlockUI -->


     <div class="mainDiv">
     
     
         <div class="innermainDiv">
         
            <%@ include file="template/innermenu.jsp" %>
        
           
           <div id="fade"></div>
      
      <img src="" id="attendencerealimage">
     
        <div id="modal">
            <img id="loader" src="<c:url value="/resources/images/loading.gif" />" />
        </div>
      </img> 
            <div style="height:50px;text-align:left;font-family:Verdana, Arial, Helvetica, sans-serif;color:#333333;font-size:13px;padding-top: 34px;width: 826px;margin: 0 auto;font-weight: bold;font-size: 12px;">
                        <table>
                            <tbody>
                                <tr>
                                    <td valign="top">
                                         <input type="checkbox" id="chkConsent" value="1">
                                    </td>
                                    <td valign="top" style="padding-left:5px" class="">
                                        <span class="" contenteditable="false" Style="color: #292424;" >I hereby state that I have no objection in authenticating myself with Aadhaar based authentication system and consent to provide my Aadhaar Number, Otp for Aadhaar based know your customer.</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table><br>
              </div>
           
           
           <div class="mainForm1">
         
            <br>
            <br>
         
          <c:url var="bioauthForm" value="processBioAuth.html" />
             <form:form id="bioauthForm" name="bioauthForm"  modelAttribute="biouser" action="${bioauthForm}">
             
                 <div class="mainaadharForm">
                 
                     <div class="form-group">
                        <label class="col-md-2 control-label">Aadhaar Number</label>
                         <div class="col-md-10">
                         
                                    <input type="text" id="txtAadhaarNo" name="txtAadhaarNo" class="form-control"/>
                                    
                         </div>
                         
                  </div> 
                          
                     <div class="form-group">
                        <label class="col-md-2 control-label">Auth Type</label>
                         <div class="col-md-10 col-md-offset-2" style="width: 200px;">
                         
                         
                           
                           <div class="checkbox" style="margin-top: 5px;float: left;width: 200px;">
                         
                                    <input type="checkbox" id="chkotpsms" name="chkotpsms" value="OTPSMS" onclick="EnableDisableProceedButton()" style="float:left">
                                    <label style="float:left;margin-left: 4px;">SMS</label> 
                                     
                           </div>
                           
                            <div class="checkbox" style="float: left;width: 200px;margin-top: 5px;">
                         
                                    <input type="checkbox" id="chkotpmail" name="chkotpmail" value="OTPMAIL" onclick="EnableDisableProceedButton()" style="float:left;">
                                    <label style="float: left;margin-left: 5px;">EMAIL</label> 
                                     
                            </div>
                           
                         </div>
                     </div>    
                     <div class="form-group">  
                         <div class="col-md-14">
                             <input type="button" class="generate-otp" id="generate-otp" onclick="return generateOtp()" value="Generate OTP">
                         
                         </div>
                         
                     </div>
                          <div class="form-group">
                   
                               <div id="outputdetails">
                                </div>
                          </div>
                         
                  
                     
                      <div class="form-group">
                        <label class="col-md-2 control-label">OTP</label>
                         <div class="col-md-10" style="padding-left: 100px;">
                                    <input type="text" id="txtOtpNo" name="txtOtpNo" class="form-control disabled" placeholder="Enter OTP" />
                         </div>
                    </div>  
                    
                     <input type="hidden" id="hdnSession" value="<%= session.getAttribute("user_login_name") %>" />
             
                    <div class="form-group">
                        <div class="col-md-offset-2 col-md-11">
                      <input type="button" value="Send Request" id="send_otp_request" class="send_otp_request btndisabled">
                   </div>
                   </div>
                 
                 
                 </div>
             
             </form:form>
         
        <div id="demo-result-data"> 
          </div>
   
   
         </div>  
         
         
         
         </div>
     
     
     
   <%@ include file="template/footer.jsp" %>

<script type="text/javascript">

var redirect = 'OtpProcess.html';
function onProceed() {
	
	var aadhaarno     = $('#txtAadhaarNo').val();
	//alert(aadhaarno);
	
	$.ajax({
		
		
		type : "POST",
		url : "<c:url value="/OtpGeneration.html" />",
		processData: false,
		data: "aadharnumber="+aadhaarno,
		
		success : function(data) {
			window.location.replace(redirect);
		},
		error : function(e) {
			console.log("ERROR: ", e);
			display(e);
		}
		
		
		
	});

	
	
}



</script>


<script type="text/javascript" language="javascript">
function generateOtp()
{
	var aadhaarno     = $('#txtAadhaarNo').val();
	var showData = $('#outputdetails');
	 
	
	 var chkConsent = $('#chkConsent').is(":checked");
	 var chkSms = $('#chkotpsms').is(":checked");
	 
	 var chkMail = $('#chkotpmail').is(":checked");
	 
	 if(aadhaarno ==null||aadhaarno=="")
	  {
	     alert("Aadhaar Number must be filled out");
	     return false;
 	  }
    
    if (aadhaarno.length < 12) {
    	 alert("Invalid Aadhaar Number");
        return false;
    }
    if (aadhaarno.length > 12) {
    	alert("Invalid Aadhaar Number");
        return false;
    }
	 
    if(chkConsent ==false)
	 {
	    
	    alert("Please checked the consent");
        return false;
	 }
    
    if(chkSms ==false&&chkMail==false)
	 {
	    
	    alert("Please select the Auth Type");
       return false;
	 }
    
	if(aadhaarno!=null&&chkConsent!=false)
	{
		showData.empty();
		$.ajax({
			
			
			type : "POST",
			url : "<c:url value="/OtpGeneration.html" />",
			processData: false,
			data: "aadharnumber="+aadhaarno+"&chkSms="+chkSms+"&chkMail="+chkMail,
			beforeSend : function() {
    			  
                $('#modal').css("display", "block");
                $('#fade').css("display", "block");
               },
			success : function(data) {
				
				 var finaldata = JSON.parse(data);
				 var status = finaldata.status;
				 
				 if(status=="1")
				   {
				     
				       $('#txtOtpNo').removeClass("disabled");
				       $('#send_otp_request').addClass("enabled");
				       $('#send_otp_request').removeClass("btndisabled");
				   }
			   else
				   {
				     
				      $('#txtOtpNo').addClass("disabled");
				      $('#send_otp_request').addClass("btndisabled");
				   }
				 
				
				   var content = '<blink><span style="font-weight: bold;color: #855656;font-size: 12px;">'+finaldata.message+'</span></blink>';
				
				   var list = $('<div id="ekyctable"/>').html(content);
				   showData.append(list); 
				   $('#modal').css("display", "none");
		           $('#fade').css("display", "none");
			},
			error : function(e) {
				console.log("ERROR: ", e);
				display(e);
			}
			
			
			
		});
	}
	
	else
	{
	
	  alert("Aadhaar Number Is Required!");
      return false;
	
	}
  
	
}
</script>


<script type="text/javascript" language="javascript">

$('#send_otp_request').click(function(event) {
	
	var demo_result_data = $('#demo-result-data');
	demo_result_data.empty();
	var uid     = $('#txtAadhaarNo').val();
	var otp     = $('#txtOtpNo').val();
	if(otp!=null)
		{
		
		
      $.ajax({
			
			
			type : "POST",
			
			url : "<c:url value="/OtpProcessSend.html" />",
			processData: false,
			data: "uid="+uid+"&otp="+otp,
			beforeSend : function() {
    			  
                $('#modal').css("display", "block");
                $('#fade').css("display", "block");
               },
			success : function(data) {
				 var finaldata = JSON.parse(data);
				
				 
				 var aadharheading="";transactionheading="";messageheading="";
				 var aadharresult="";transactionresult="";messageresult="";resultrow1="";resultrow="";
				 var demoresultlisttable = '<table class="gridtable"><tbody>';
              	
				 
				 
            	  var aadharheading='<tr><th>AADHAAR NUMBER</th>';
            	  var transactionheading='<th>TRANSACTION ID</th>';
            	  var messageheading='<th>STATUS</th></tr>';
            	  
            	  if(finaldata.aadhaar !="")
     	    	    {
            		  aadharresult ='<td>'+finaldata.aadhaar+'</td>';
     	    	    }
         	       if(finaldata.otpbiotransactionnm !="")
     	    	   {
         	    	  transactionresult ='<td>'+finaldata.otpbiotransactionnm+'</td>';
     	    	   }
         	      if(finaldata.status=="1")
         	    	  {
         	    	      
         	    	      if(finaldata.otpmessage !="")
       	    	          {
           	    	         messageresult ='<td style="font-weight: bold;color: green;">'+finaldata.otpmessage+'</td>';
       	    	          }
         	    	     
         	    	  }
         	      else
         	    	  {
         	    	    
         	    	        if(finaldata.otpmessage !="")
       	    	             {
           	    	           messageresult ='<td style="font-weight: bold;color: red;">'+finaldata.otpmessage+'</td>';
       	    	             }
         	    	  }
         	   
         	   
            	  
            	  resultrow=aadharheading+transactionheading+messageheading;
            	  resultrow1=aadharresult+transactionresult+messageresult;
            	  
            	  var demoresultlisttableend = '</tbody></table>';
            	  
            	  var demoresultlist = $('<div class="outPut"  style="clear: both;padding-top: 25px;padding-bottom: 40px;">').html(demoresultlisttable+resultrow+resultrow1+demoresultlisttableend);
				  demo_result_data.append(demoresultlist);
				  $('#modal').css("display", "none");
                  $('#fade').css("display", "none");
				 
			},
			error : function(e) {
				console.log("ERROR: ", e);
				display(e);
			}
			
			
			
		});
		
		
		
		
		}
	else
		{
		
		 alert("Otp is required");
		}
	
	

});
</script>

