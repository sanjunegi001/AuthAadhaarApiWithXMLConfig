<%@ include file="template/header.jsp" %>
<script type="text/javascript">

function isBIOChecked()
{
	
	return $('#chkbioFP').is(':checked')
}

	
	
$('#txtAadhaarNo').keyup(function () {
	
	
    EnableDisableProceedButton();
});


function EnableDisableProceedButton() {
	
	
	 document.getElementById('chkbioFP').disabled = false;
     //document.getElementById('chkFP').disabled=false;
     //document.getElementById('chktwoFP').disabled=false;
    // document.getElementById('chkOtp').disabled=false;
     
     var txtAadhaarValue = $('#txtAadhaarNo').val();
     
    if ($.trim(txtAadhaarValue).length < 12) {
    	alert("Invalid Aadhaar Number");
        $('#errorMessage').text('');
        document.getElementById('btnProceed').disabled = true;
        return;
    }
   

    if ($.trim(txtAadhaarValue).length > 12) {
    	alert("Invalid Aadhaar Number");
    	
        //$('#errorMessage').text('Invalid Aadhaar Number');
        document.getElementById('btnProceed').disabled = true;
        return;
    }

    var isAadhaarNumberValid = checkverhoff($('#txtAadhaarNo').val());
   
    
    if (isAadhaarNumberValid === false) {
        document.getElementById('btnProceed').disabled = true;
        document.getElementById('chkbioFP').disabled = false;
        //document.getElementById('chkFP').disabled=false;
        //document.getElementById('chktwoFP').disabled=false;
        //document.getElementById('chkOtp').disabled=false;
        alert("Invalid Aadhaar Number");
        return;
    }

    if((isBIOChecked())&& isAadhaarNumberValid)
    	{
    	
    	document.getElementById('btnProceed').disabled = false;
    	//document.getElementById('chkFP').disabled=true;
        //document.getElementById('chktwoFP').disabled=true;
        //document.getElementById('chkOtp').disabled=true;
    	
    	 
    	}
    
    
    else {
    	
          document.getElementById('btnProceed').disabled = true;
          $('#errorMessage').text('');
    }
 
    
    //$('#btnProceed').removeAttr("disabled");
   
}




function checkverhoff(value) {
	
    var d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
    var p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];
    var j = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

    if ($.trim(value) === '')
        return false;

    var c = 0;
    value.replace(/\D+/g, "").split("").reverse().join("").replace(/[\d]/g, function (u, i, o) {
        c = d[c][p[i & 7][parseInt(u, 10)]];
    });
    return (c === 0);
}





</script>

<div class="bfd">

 <div class="blockUIbfd" style="display:none;">

   <div class="blockUIbfd blockMsg blockPage" style="z-index: 1011; position: absolute; padding: 0px; margin: 0px; width: 575px; color: rgb(0, 0, 0); cursor: wait; background-color: rgb(255, 255, 255); top: 92px; text-align: center; height: 180px; border: 3px solid rgb(170, 170, 170);">
      <div id="divSettings" style="cursor: default; width: 575px; height: 100%; text-align: center; padding-top: 56px; padding-left: 55px;">
        <table style="margin-left:15px;margin-right:15px">
          <tbody>
            <tr>
               <td>
                  <span style="font-size:18px;float:left;">Please choose Fingerprint device : </span>
                </td>
                 <td>
                   <%if(session.getAttribute("user_login_name").toString().contains("elitmus")){%>
                 
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                             
                    </select>
                    
                    <%}else{ %>
                    
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                            <!--   <option value="STARTEK_FM220">Startek FM220</option>
                             <option value="MFS100">MFS 100</option>-->
                    </select>
                    <%} %>
              </td>
          </tr>
          <tr>
             <td colspan="2">
              <br>
             </td>
         </tr>
         <tr>
          <td colspan="2">
          <input type="button" value="Ok" onclick="savebfdSwitchDevice();" style="height: 32px;width: 117px;">
          </td>
        </tr>
        </tbody>
      </table>
    </div>
  </div>

</div>

</div>

<div class="twofinger">

 <div class="blockUI123" style="display:none;">

   <div class="blockUI123 blockMsg blockPage" style="z-index: 1011; position: absolute; padding: 0px; margin: 0px; width: 575px; color: rgb(0, 0, 0); cursor: wait; background-color: rgb(255, 255, 255); top: 92px; text-align: center; height: 180px; border: 3px solid rgb(170, 170, 170);">
      <div id="divSettings" style="cursor: default; width: 575px; height: 100%; text-align: center; padding-top: 56px; padding-left: 55px;">
        <table style="margin-left:15px;margin-right:15px">
          <tbody>
            <tr>
               <td>
                  <span style="font-size:18px;float:left;">Please choose Fingerprint device : </span>
                </td>
                 <td>
                   <%if(session.getAttribute("user_login_name").toString().contains("elitmus")){%>
                 
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                             
                    </select>
                    
                    <%}else{ %>
                    
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                            <!--   <option value="STARTEK_FM220">Startek FM220</option>
                             <option value="MFS100">MFS 100</option>-->
                    </select>
                    <%} %>
              </td>
          </tr>
          <tr>
             <td colspan="2">
              <br>
             </td>
         </tr>
         <tr>
          <td colspan="2">
          <input type="button" value="Ok" onclick="saveTWOFingerSwitchDevice();" style="height: 32px;width: 117px;">
          </td>
        </tr>
        </tbody>
      </table>
    </div>
  </div>

</div>

</div>


<!-- End BlockUi -->


<!-- BlockUI -->

<div class="bodyblockUI">

 <div class="blockUI" style="display:none;">

   <div class="blockUI blockMsg blockPage" style="z-index: 1011; position: absolute; padding: 0px; margin: 0px; width: 575px; color: rgb(0, 0, 0); cursor: wait; background-color: rgb(255, 255, 255); top: 92px; text-align: center; height: 180px; border: 3px solid rgb(170, 170, 170);">
      <div id="divSettings" style="cursor: default; width: 575px; height: 100%; text-align: center; padding-top: 56px; padding-left: 55px;">
        <table style="margin-left:15px;margin-right:15px">
          <tbody>
            <tr>
               <td>
                  <span style="font-size:18px;float:left;">Please choose Fingerprint device : </span>
                </td>
                 <td>
                   <%if(session.getAttribute("user_login_name").toString().contains("elitmus")){%>
                 
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                             
                    </select>
                    
                    <%}else{ %>
                    
                    <select id="fpDrivers">
                             
                             <option value="MORPHO_1300E3">Morpho MSO1300E3</option>
                             <option value="STARTEK_FM220">Startek FM220</option>
                             <option value="MFS100">MFS 100</option>
                    </select>
                    <%} %>
              </td>
          </tr>
          <tr>
             <td colspan="2">
              <br>
             </td>
         </tr>
         <tr>
          <td colspan="2">
          <input type="button" value="Ok" onclick="saveFMRSelectionAndSwitchDevice();" style="height: 32px;width: 117px;">
          </td>
        </tr>
        </tbody>
      </table>
    </div>
  </div>

</div>

</div>


<!-- End BlockUi -->


     <div class="mainDiv">
     
         <div class="innermainDiv">
         
         <%@ include file="template/innermenu.jsp" %>
          
         
         
         
         
         <div class="mainForm1">
         
            <br>
            <br>
         
          <c:url var="bioauthForm" value="processBioAuth.html" />
             <form:form id="bioauthForm" name="bioauthForm"  modelAttribute="biouser" action="${bioauthForm}">
             
                 <div class="mainaadharForm">
                 
                     <div class="form-group">
                        <label class="col-md-2 control-label">Aadhaar Number</label>
                         <div class="col-md-10">
                                    <input type="text" id="txtAadhaarNo" name="txtAadhaarNo" class="form-control" placeholder="Enter Aadhaar number" />
                                    
                         </div>
                     </div>
                    
                     <input type="hidden" id="hdnSession" value="<%= session.getAttribute("user_login_name") %>" />
                      
                    
                     <%if(session.getAttribute("user_login_name").toString().contains("elitmus")){%>
                     
                       
                    <div class="form-group">
                        <label class="col-md-2 control-label">Name</label>
                         <div class="col-md-102">
                                    <input type="text" id="txtusername" name="txtusername" class="form-control" placeholder="Enter Name" />
                                    
                         </div>
                     </div> 
                           
                     <div class="form-group">
                        <label class="col-md-2 control-label">User Email</label>
                         <div class="col-md-101">
                                    <input type="text" id="txtuseremail" name="txtuseremail" class="form-control" placeholder="Enter Email Adress" />
                                    
                         </div>
                     </div>

                      <% }%> 
                   
                     
                    <div class="form-group">
                        <label class="col-md-2 control-label">Auth Type</label>
                         <div class="col-md-10 col-md-offset-2" style="width: 200px;">
                         
                         
                           
                           <div class="checkbox" style="margin-top: 5px;float: left;width: 200px;">
                         
                                    <input type="checkbox" id="chkbioFP" name="chkbioFP" value="BIOFMR" onclick="EnableDisableProceedButton()" style="float:left">
                                    <label style="float:left;margin-left: 4px;">Biometrics</label> 
                                     
                           </div>
                           <!--  
                            <div class="checkbox" style="float: left;width: 200px;margin-top: 5px;">
                         
                                    <input type="checkbox" id="chkFP" name="chkFP" value="FMR" onclick="EnableDisableProceedButton()" style="float:left;">
                                    <label style="float: left;margin-left: 5px;">BFD</label> 
                                     
                            </div>
                            -->
                         <!--  
                           <div class="checkbox" style="margin-top: 5px;float: left;width: 200px;">
                         
                                    <input type="checkbox" id="chktwoFP" name="chktwoFP" value="TWOFINGER" onclick="EnableDisableProceedButton()" style="float:left;">
                                    <label style="float:left;margin-left: 4px;">Two Finger</label>  
                                     
                           </div>
                         -->  
                          <!--  <div class="checkbox" style="margin-top: 5px;float: left;width: 200px;">
                         
                                    <input type="checkbox" id="chkOtp" name="chkOtp" value="OTP" onclick="EnableDisableProceedButton()" style="float:left;">
                                    <label style="float:left;margin-left: 4px;">Otp</label>  
                                     
                           </div> -->
                            
                             
                           
                         
                         
                         </div>
                     </div>
                     
                    <div class="form-group">
                        <div class="col-md-offset-2 col-md-11">
                          <input class="btn btn-default" id="btnProceed" type="button" onclick="onProceed()" value="Proceed" disabled="disabled">
                        </div>
                    </div>
                 
                 
                 </div>
             
             
             
             </form:form>
         
         
         
         
         </div>  
         
         
         
         </div>
     
     
     
      <%@ include file="template/footer.jsp" %>



<script type="text/javascript">

function onProceed() {
	
	
	//var sessionval = document.getElementById('hdnSession').value;
	if(document.getElementById('hdnSession').value == "elitmus")
		{
		
		   var name = document.getElementById('txtusername').value;
		   if(name == null || name =="")
			   {
			      alert("Name Filed Is Required");
			      return false;
			   }
		
		
		
		  var emailsession = document.getElementById('txtuseremail').value;
		  
		  var reg = /^([A-Za-z0-9_\-\.])+\@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$/;
		  
		  if(emailsession==null || emailsession=="" )
			  {
			      alert("Email Field Is Required");
			      return false;
			  }
		  
		  else if(!emailsession.match(reg)) {
			    alert("Invalid email address");
			    return false;
			  }

		}
	
	var aadhaarno     = $('#txtAadhaarNo').val();
	var txtusername  = $('#txtusername').val();
	var txtuseremail  = $('#txtuseremail').val();
	
	
	var fingertype = $('#chkFP:checked').val();
	var devicevalue = $('#fpDrivers').val();
    var biofingertype    = $('#chkbioFP:checked').val();
    var twofingertype    = $('#chktwoFP:checked').val();
    //var otptype    = $('#chkOtp:checked').val();
  
    
 if(fingertype=="FMR") 
	 {
	 
	
	 $('.bfd').block({
		 
			
		    message: $('.blockUIbfd'),
		    centerX: true,
		    centerY: true,
		    css: {
		        width: '600px',
		        height: '300px',
		        border: '3px solid #FF9900',
		        backgroundColor: '#000',
		        color: '#fff',
		        padding: '25px'
		    }
	 
	    
	 
	 
	    });
	 
	 }
 
 else if(twofingertype =="TWOFINGER")
	 {
	 
	 $('.twofinger').block({
		 
			
		    message: $('.blockUI123'),
		    centerX: true,
		    centerY: true,
		    css: {
		        width: '600px',
		        height: '300px',
		        border: '3px solid #FF9900',
		        backgroundColor: '#000',
		        color: '#fff',
		        padding: '25px'
		    }
	 
	    
	 
	 
	    });
	 
	
	 }

 
 else if(biofingertype =="BIOFMR")
	 {
	  
	 
	 $('.bodyblockUI').block({
	 
		
		    message: $('.blockUI'),
		    centerX: true,
		    centerY: true,
		    css: {
		        width: '600px',
		        height: '300px',
		        border: '3px solid #FF9900',
		        backgroundColor: '#000',
		        color: '#fff',
		        padding: '25px'
		    }
	 
	    
	 
	 
	    });
	 
	  
	 
	 
	 
	 }
   
	
}




function saveTWOFingerSwitchDevice()
{
	
 
	  var aadhaarno     = $('#txtAadhaarNo').val();
	    var biofingertype    = $('#chktwoFP:checked').val();
		var devicevalue = $('#fpDrivers').val();
		
		var txtusername  = $('#txtusername').val();
		var txtuseremail  = $('#txtuseremail').val();
		
		
		
		var redirect2 = 'tbioAuth.html';
		
		  $.ajax({
		    	 
		    	 type : "POST",
					
					url : "<c:url value="/processBioAuth.html" />",
					processData: false,
					data: "txtAadhaarNo=" + aadhaarno +"&txtusername="+txtusername+"&txtuseremail="+txtuseremail+"&chkFP=" + biofingertype +"&deviceType="+devicevalue,
					success : function(data) {
						
						window.location.replace(data);
					},
					error : function(e) {
						console.log("ERROR: ", e);
						display(e);
					}
					
		    	 
		    	 
		     });
		
}

function saveFMRSelectionAndSwitchDevice()
{
	
	
	
    var aadhaarno     = $('#txtAadhaarNo').val();
    var biofingertype    = $('#chkbioFP:checked').val();
	var devicevalue = $('#fpDrivers').val();
	
	var txtusername  = $('#txtusername').val();
	var txtuseremail  = $('#txtuseremail').val();
	
	
	var redirect = '/startek220.html';
	
	$.ajax({
		
		
		type : "POST",
		
		url : "<c:url value="/processBioAuth.html" />",
		processData: false,
		data: "txtAadhaarNo=" + aadhaarno +"&txtusername="+txtusername+"&txtuseremail="+txtuseremail+"&chkFP=" + biofingertype +"&deviceType="+devicevalue,
		
		success : function(data) {
			
			window.location.replace(data);
		},
		error : function(e) {
			console.log("ERROR: ", e);
			display(e);
		}
		
		
		
	});

	
	
}


function savebfdSwitchDevice()
{
	
	
	
    var aadhaarno     = $('#txtAadhaarNo').val();
    var biofingertype    = $('#chkFP:checked').val();
	var devicevalue = $('#fpDrivers').val();
	
	var txtusername  = $('#txtusername').val();
	var txtuseremail  = $('#txtuseremail').val();
	
	
	var redirect = '/startek220.html';
	
	$.ajax({
		
		
		type : "POST",
		
		url : "<c:url value="/processBioAuth.html" />",
		processData: false,
		data: "txtAadhaarNo=" + aadhaarno +"&txtusername="+txtusername+"&txtuseremail="+txtuseremail+"&chkFP=" + biofingertype +"&deviceType="+devicevalue,
		
		success : function(data) {
			
			window.location.replace(data);
		},
		error : function(e) {
			console.log("ERROR: ", e);
			display(e);
		}
		
		
		
	});

	
	
}


</script>

