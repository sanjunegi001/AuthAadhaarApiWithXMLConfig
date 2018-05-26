<%@ include file="template/header.jsp" %>


<div class="mainDiv">

   <div class="innermainDiv">
  
<%@ include file="template/innermenu.jsp" %>
         
          <div id="fade"></div>
      
      <img src="" id="attendencerealimage">
     
        <div id="modal">
            <img id="loader" src="<c:url value="/resources/images/loading.gif" />" />
        </div>
      </img> 
         
         <div class="mainForm">
             <script>
             function validateForm() {
            	var count=0;
            	 
            	 var inputaadhaar= document.myform.aadharnumber.value;
                 var inputname   =  document.myform.name.value;
                 var alphaExp = /^[a-zA-Z]+$/;
                 var year   = document.myform.year.value;
                 var month  = document.myform.month.value;
                 var date   = document.myform.date.value;
                 
                 var mobileno   = document.myform.mobileno.value;
                 var email   = document.myform.email.value;
                 
                 /****/
                 
                 var gender         = document.myform.gender.value;
                 var addressvlaue   = document.myform.strAddressValue.value;
                 var careOf         = document.myform.strCareOf.value;
                 var building       = document.myform.strBuilding.value;
                 var landmark       = document.myform.strLandmark.value;
                 var street         = document.myform.strStreet.value;
                 var locality       = document.myform.strLocality.value;
                 var poname         = document.myform.strPoName.value;
                 var vtc            = document.myform.strVillage.value;
                 var subdist        = document.myform.strSubdist.value;
                 var dist           = document.myform.strDistrict.value;
                 var state          = document.myform.strState.value;
                 var pincode        = document.myform.strPincode.value;
                 
                 var chkConsent = $('#chkConsent').is(":checked");
                 
                 
                 if(inputaadhaar ==null||inputaadhaar=="")
             	  {
             	     alert("Aadhaar Number must be filled out");
             	     return false;
              	  }
                 
                 if (inputaadhaar.length < 12) {
                 	 alert("Invalid Aadhaar Number");
                     return false;
                 }
                 if (inputaadhaar.length > 12) {
                 	alert("Invalid Aadhaar Number");
                     return false;
                 }

                 
                 if(chkConsent ==false)
                	 {
                	    
                	    alert("Please checked the consent");
             	        return false;
                	 }
                  
                 var group1 = false; var group2 = false;
                 if(inputname.trim().length !=0)
            	  {
                	 count++;
                	 group1 = true;
             	  }
                 
                  if(year.trim().length != 0)
                	  {
                	  count++;
                	  group1 = true;
                	  }
                  if(month.trim().length != 0)
            	  {
            	    group1 = true;
            	  }
                  
                  if(date.trim().length != 0)
            	  {
            	    group1 = true;
            	  }
                  if(gender.trim().length != 0)
            	  {
                	  count++;
            	    group1 = true;
            	  }
                  
                  if(mobileno.trim().length != 0)
            	  {
                	  count++;
            	    group1 = true;
            	  }
                  
                  if(email.trim().length != 0)
            	  {
                	count++;
            	    group1 = true;
            	  }
                  
                  if(addressvlaue.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(careOf.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(building.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(landmark.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(street.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(locality.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(poname.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(vtc.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(subdist.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(dist.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(state.trim().length !=0)
                  {
                	 group2 = true;
                  }
                  if(pincode.trim().length !=0)
                  {
                	 group2 = true;
                  }
           
                 if(group1 == false && group2 == false)
                	 {
                	   alert("Please enter PI OR PFA OR PA value for verification");
                	   return false;
                	 }
                 else if(count>1){
                	 
                	 alert("Please enter only one PI  value for verification at a time");
              	   return false;
                 }
                 else
                	 {
                	   
                	 hoemAuthentication();
                	 
                	 }
           
                if(isNaN(inputaadhaar))
   		          {
   		            alert("Aadhaar Number must be Number");
       	            return false;
   		          } 
            	 
             }
             </script>
         
               

                  <form:form id="aadharForm" name="myform" modelAttribute="user" action="">
                  
                  
                     <div class="mainaadharForm">
                     
                        <div id="main_top_auth_aadhaar" style="margin-top: 39px;">
                          
                            <div id="main_aadhaar_number">
                                <lable style="font-weight: bold;font-size: 14px;">Aadhaar Number<span style="color:red">*</span></lable>
                                <input type="text" name="aadharnumber" id="labelaadhar_input" style="margin-left: 4px;width: 309px;border: 1px solid #ccc;height: 23px;border-radius: 5px; "></input>
                             
                             </div>
                        
                        </div>
                        
                         <div style="width:100%;height:50px;text-align:left;font-family:Verdana, Arial, Helvetica, sans-serif;color:#333333;font-size:13px;width: 800px;margin: 0 auto;padding-top: 15px;">
                        <table>
                            <tbody>
                                <tr>
                                    <td valign="top">
                                        <input type="checkbox" id="chkConsent" value="1">
                                    </td>
                                    <td valign="top" style="padding-left:5px" class="">
                                        <span class="" contenteditable="false">I hereby state that I have no objection in authenticating myself with Aadhaar based authentication system and consent to provide my Aadhaar Number and Demographic Details for Aadhaar based know your customer.</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table><br>
                    </div>
                        
                        
                        <div id="main_bottom_auth_aadhaar">
                       
                       
                           <table style="width: 800px; margin-left: auto; margin-right: auto; padding: 10px; font-weight: normal; font-size: small;">
                           
                             <tr>
								<td style="width: 400;">
									
										
										<div style="border: 1px solid #F5DA81;margin: 10px;padding: 5px;width: 772px;float: left;">
										
										  <div style="width: 772px;margin: 0 auto;padding-top: 14px;padding-bottom: 13px;float: left;">
										
										
										    <div id="top_left" style="float: left;width: 400px;margin-top: 11px;">
										       <table style="margin-left: 11px;">
												<tr>
													<td align="right">Name</td>
														
													<td colspan="1"><input type="text" name="name" id="name" tabindex="2" style="margin-left: 4px;width: 210px;border: 1px solid #ccc;height: 23px;border-radius: 5px;"/></td>
														
												</tr>
												
												<tr style="height:10px"><td colspan="3"></td></tr>
												
												
													<tr>
													<td align="right" style="width: 100px;">Match Strategy</td>
													<td style="padding-left: 6px;width: 88px;float: left;">
													
													  <input type="radio" checked="checked" class="piMatchStrategyExact" name="matchvalue"  id="name_exact_match" value="E" align="left" tabindex="5" style="padding-right: 5px;">Exact Match</input>
													
													</td>
													
													<td align="left" style="padding-left: 6px;float: left;">
													 <input type="radio" class="piMatchStrategyExact" name="matchvalue" id="name_partial_match" value="P" align="left" tabindex="6" style="padding-right: 5px;">Partial Match</input>
													
													</td>
												</tr>
												
											
												<tr>
													<td align="right" style="vertical-align: middle;">Match Value</td> 
													<td colspan="1">
													<input type="text" name="matchingvalue" id ="name_matchingvalue" tabindex="11" value="100" maxlength="20" style="width: 82px;border: 1px solid #ccc;height: 17px;border-radius: 5px;
    margin-top: 5px;margin-left: 8px;float: left;" onkeypress="return isNumberNameKey(event)"/>
													</td>
													
												</tr>
										
											
												
										      </table>
										    
										    </div>
										    <div id="top_right" style="float: right;width: 300px;">
										    
										   <table>
										   
												<tr style="height:10px"><td colspan="2"></td></tr>
												<tr>
													<td align="right">Gender</td>
													<td colspan="1"><select name="gender" id="gender" tabindex="4" style="float: left;border-radius: 5px;margin-left: 6px;">
															<option value="">SELECT GENDER</option>
															<option value="M">MALE</option>
															<option value="F">FEMALE</option>
															<option value="T">TRANS GENDER</option>
													</select></td>
												</tr>
												
												<tr style="height:10px"><td colspan="2"></td></tr>
												
											   <tr>
													<td align="right">Date Of Birth</td>
														
													<td >
													
													   <input type="text" name="year" id="labelaadhar_input"  maxlength="4" style="width:121px;height: 21px;margin-left: 5px;float: left;"></input>
                                                       <input type="text" name="month" id="labelaadhar_input" maxlength="2" style="width:40px;height: 21px;float: left;margin-left: 2px;"></input>
                                                       <input type="text" name="date" id="labelaadhar_input" maxlength="2" style="width:40px;height: 21px;float: left;margin-left: 5px;"></input>
													   
													
													</td>
														
												</tr>
												
												
												
												
												
												<tr>
													<td align="right">&nbsp</td>
														
													<td >
													
													 <label style="font-weight: bold;font-size: 12px;color: #666666;width: 90px;">YYYY</label>
													  <label style="font-weight: bold;font-size: 12px;color: #666666;width: 71px;">MM</label>
													   <label style="font-weight: bold;font-size: 12px;color: #666666;width: 36px;">DD</label>   
													
													</td>
														
												</tr>
												<tr>
													
													<td align="right">Mobile no.</td>
													<td><input type="text" name="mobileno" id ="mobileno" maxlength="10" style="width: 121px;height: 21px;margin-left: 5px;float: left;" onkeypress="return isNumberNameKey(event)"/></td>
												</tr>
												
												<tr>
													
													<td align="right">Email</td>
													<td><input type="text" name="email" id="email"   style="width:150px;height: 21px;margin-left: 5px;float: left;"></input></td>
												</tr>
												<tr>
												<td >
													
													 <label style="font-weight: bold;font-size: 12px;color: #666666;width: 50px;">(eg:abc@gmail.com)</label>
													 </td>
												</tr>
												
												
											</table>
										   		    
										    </div>
										
								
										</div>	
											
										</div>
									
								</td>
                             </tr>
                           
                           
                           
                           </table>
                       
                       
                        <table style="width: 800px; margin-left: auto; margin-right: auto; padding: 10px; font-weight: normal; font-size: small;">
                         
                            
                            <tr>
                            
                               <td style="font-weight: normal;width: 250px;float: left;">
									
										<div style="border: 1px solid #F5DA81; margin: 10px; padding: 5px;">
											<table>
												<tr>Address value</tr>
												
												<tr>
													<td colspan="3" width="100%">
													<textarea rows="4" name="strAddressValue" id="strAddressValue" tabindex="7" style="width: 200px;"></textarea>
															
													</td>
												</tr>
												<tr style="height: 18px;">
												<td colspan="3"></td>
												
												</tr>
												
												
												<tr>
													<td style="width:90px"><label style="font-weight: normal;">Match Strategy</label></td>
													<td><input type="radio" checked="checked" class="pfaMatchStrategy" name="strPfaMatchStrategy" id="strPfaExactMatched" value="E" tabindex="8" style="padding-right: 5px;">Exact Match</input></td>
														
														
													</td>

												</tr>
												
													<tr style="height: 23px;">
													<td style="width:90px">&nbsp;</td>
													<td><input type="radio" class="pfaMatchStrategy" name="strPfaMatchStrategy" id="strPfaPartialMatch" value="P" tabindex="9" style="padding-right: 5px;">Partial Match</input>
												
														
													</td>

												</tr>
												
												<tr>
												
												</tr>	
												
												<tr style="height: 40px;">
													<td style="width:90px"><label style="font-weight: normal;margin-left: -16px;">Match Value</label> </td>
													<td colspan="1">
													  <input type="text" name="strAddressMatchvalue" tabindex="11" id="strAddressMatchvalue" value="100" style="width: 82px;border: 1px solid #ccc;height: 17px;border-radius: 5px;" onkeypress="return isNumberPfaKey(event)"/>
													</td>
													
												</tr>
											</table>
										</div>
									
								</td>
                             
                               <td style="font-weight: normal;width: 550px;float: left;">
									
										<div style="border: 1px solid #F5DA81; margin: 10px; padding: 5px">
											
											<table>
												<tr>
													<td align="right" style="vertical-align:middle">Care Of</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strCareOf" id="strCareOf" tabindex="10" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
													<td align="right" style="vertical-align:middle">Building</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strBuilding" id="strBuilding" tabindex="11" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
												</tr>
												<tr>
													<td align="right" style="vertical-align:middle">Landmark</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strLandmark" id="strLandmark" tabindex="12" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
													<td align="right" style="vertical-align:middle">Street</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strStreet" id="strStreet" tabindex="13" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
												</tr>
												<tr>
													<td align="right" style="vertical-align:middle">Locality</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strLocality" id="strLocality" tabindex="14" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
													<td align="right" style="vertical-align:middle">PO Name</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strPoName" id="strPoName" tabindex="15" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
												</tr>
												<tr>
													<td align="right" style="vertical-align:middle">Village/Town/City</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strVillage" id="strVillage" tabindex="16" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
													<td align="right" style="vertical-align:middle">Subdist</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strSubdist" id="strSubdist" tabindex="17" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
												</tr>
												
												<tr>
													<td align="right" style="vertical-align:middle">District</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strDistrict" id="strDistrict" tabindex="18" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
													<td align="right" style="vertical-align:middle">State</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strState" id="strState" tabindex="19" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
												</tr>
														
											   <tr>
													<td align="right" style="vertical-align:middle">Pincode</td>
													<td style="float:left;width:150px;padding-left: 4px;padding-bottom: 4px;"><input type="text" name="strPincode" id="strPincode" tabindex="20" style="width: 150px;border: 1px solid #ccc;height: 23px;border-radius: 5px;" /></td>
														
														
												</tr>
																		
												
													
												
											</table>
										</div>
									
								</td>
                               
                               
                               
                               </td>
                            
                            
                            
                            </tr>
                         
                         
                         </table>
                       
                 
                       
                        </div>
                        
                        
                        <div id="main_bottom_auth_aadhaar">
                             
                              <div class="action_buttion" style="padding-top: 30px;width: 242px;margin: 0 auto;float: none;">
                   
                                  <div class="action_buttion_auth">
                      
                                   <input type="button" value="Authenticate" id="inneraction_buttion_auth" onclick="return validateForm()">
                        
                                 </div>
                                <div class="action_buttion_cancel">
                                      <input type="cancel" value="CANCEL" id="inneraction_buttion_cancel" >
                               </div>
                   
                        </div>
                             
                        
                        </div>
                     
                     
                     
                     
                     </div>
                   </form:form>
         
         
           
          <div id="demo-result-data"> 
          </div>
         
      
         </div>
         
         <script type="text/javascript">
         
         function isNumberNameKey(e) {
        	 
        	 var number = $('#name_matchingvalue').val()
        	    if (isNaN(number)) {
        	        alert("Enter only numbers.");
        	        $('#name_matchingvalue').val('');
        	    }

        	    if (number > 100) {
        	        alert("Value entered must be 100 or lower.");
        	        $('#name_matchingvalue').val('');
        	    }
        	    
        	    var number1 = $('#mobileno').val()
        	    if (isNaN(number1)) {
        	        alert("Enter only numbers.");
        	        $('#mobileno').val('')="";
        	    }

        	   
        	
        	 
        	}
         
         </script>
         
           <script type="text/javascript">
         
         function isNumberPfaKey(e) {
        	 
        	 var number = $('#strAddressMatchvalue').val()
        	    if (isNaN(number)) {
        	        alert("Enter only numbers.");
        	        $('#strAddressMatchvalue').val('');
        	    }

        	    if (number > 100) {
        	        alert("Value entered must be 100 or lower.");
        	        $('#strAddressMatchvalue').val('');
        	    }
        	
        	 
        	}
         
         </script>
         
         
         <script type="text/javascript">
            
         $(document).ready(function() {
        	    
        	 $( ".piMatchStrategyExact" ).change(function() {
        		    switch($(this).val()) {
        		        case 'P' :
        		        	$('#name_matchingvalue').attr('readonly', false);
        		        	$('#name_matchingvalue').val('');
        		            break;
        		        case 'E' :
        		        	$('#name_matchingvalue').attr('readonly', true);
        		        	$('#name_matchingvalue').val('100');
        		            break;
        		    }            
        		});
        	 
        	 $( ".pfaMatchStrategy" ).change(function() {
        		 
        		 
        		 var pfasession = <%= session.getAttribute("user_secret_flag")%>;
        		 
        		 if(pfasession =="2")
        			 {
        			
        			 switch($(this).val()) {
      		        case 'P' :
      		        	$('#strAddressMatchvalue').attr('readonly', true);
      		        	$('#strAddressMatchvalue').val('90');
      		            break;
      		        case 'E' :
      		        	$('#strAddressMatchvalue').attr('readonly', true);
      		        	$('#strAddressMatchvalue').val('100');
      		            break;
      		              }    
        			 }
        		 else
        			 {
        			 switch($(this).val()) {
      		        case 'P' :
      		        	$('#strAddressMatchvalue').attr('readonly', false);
      		        	$('#strAddressMatchvalue').val('');
      		            break;
      		        case 'E' :
      		        	$('#strAddressMatchvalue').attr('readonly', true);
      		        	$('#strAddressMatchvalue').val('100');
      		            break;
      		             }    
        			 }
     		            
     		});
        	 
        	 
        	 
        	});
         
         
         </script>
         
         
         <script type="text/javascript">
         
            function hoemAuthentication()
            {
            	
            	
            	var demo_result_data = $('#demo-result-data');
            	demo_result_data.empty();
            	if(($('#labelaadhar_input').val() ==null)||($('#labelaadhar_input').val()==""))
            		{
            		   var labelaadhar_input ="NA";
            		}
            	else
            		{
            		 
            		   var labelaadhar_input = $('#labelaadhar_input').val();
            		
            		}
            	if(($('#name').val() ==null)||($('#name').val()==""))
        		    {
        		       var name ="";
        		     }
        	     else
        		     {
        		       var name = $('#name').val();
        		     }
            	
            	if(($("input:radio[name=matchvalue]:checked").val() ==null)||($("input:radio[name=matchvalue]:checked").val()==""))
    		         {
    		         var name_match ="";
    		         }
    	        else
    		         {
    		          var name_match = $("input:radio[name=matchvalue]:checked").val();
    		          
    		        
    		         }
            	
            	
            	if(($('#name_matchingvalue').val() ==null)||($('#name_matchingvalue').val()==""))
	             {
	             var name_matchingvalue ="";
	             }
               else
	             {
	                var name_matchingvalue = $('#name_matchingvalue').val();
	             }
        	
            	if(($('#gender').val() ==null)||($('#gender').val()==""))
	             {
	             var gender ="";
	             }
              else
	             {
	                var gender = $('#gender').val();
	             }
            	

            	if(($('#email').val() ==null)||($('#email').val()==""))
	             {
	             var email ="";
	             }
              else
	             {
	                var email = $('#email').val();
	             }
            	

            	if(($('#mobileno').val() ==null)||($('#mobileno').val()==""))
	             {
	             var mobileno ="";
	             }
              else
	             {
	                var mobileno = $('#mobileno').val();
	             }
            	
            	
            	if(($('[name=year]').val() ==null)||($('[name=year]').val()==""))
	             {
	             var year ="";
	             }
                else
	             {
	                var year = $('[name=year]').val();
	               
	             }
            	
            	if(($('[name=month]').val() ==null)||($('[name=month]').val()==""))
	             {
	             var month ="";
	             }
                else
	             {
	                var month = $('[name=month]').val();
	             }
            	
            	if(($('[name=date]').val() ==null)||($('[name=date]').val()==""))
	             {
	             var date ="";
	             }
                 else
	             {
	                var date = $('[name=date]').val();
	               
	             }
            	if(($('#strAddressValue').val() ==null)||($('#strAddressValue').val()==""))
	             {
	             var strAddressValue ="";
	             }
                else
	             {
	                var strAddressValue = $('#strAddressValue').val();
	                
	                alert(strAddressValue);
	             }
            	
            	
            	if(($("input:radio[name=strPfaMatchStrategy]:checked").val() ==null)||($("input:radio[name=strPfaMatchStrategy]:checked").val()==""))
	             {
	             var strPfaMatched ="";
	             }
               else
	             {
	                var strPfaMatched = $("input:radio[name=strPfaMatchStrategy]:checked").val();
	             }
            	
            	if(($('#strAddressMatchvalue').val() ==null)||($('#strAddressMatchvalue').val()==""))
	             {
	             var strAddressMatchvalue ="";
	             }
                else
	             {
	                var strAddressMatchvalue = $('#strAddressMatchvalue').val();
	             }
            	if(($('#strCareOf').val() ==null)||($('#strCareOf').val()==""))
	             {
	             var strCareOf ="";
	             }
                else
	             {
	                var strCareOf = $('#strCareOf').val();
	             }
            	if(($('#strBuilding').val() ==null)||($('#strBuilding').val()==""))
	             {
	             var strBuilding ="";
	             }
                else
	             {
	                var strBuilding = $('#strBuilding').val();
	             }
            	if(($('#strLandmark').val() ==null)||($('#strLandmark').val()==""))
	             {
	             var strLandmark ="";
	             }
                else
	             {
	                var strLandmark = $('#strLandmark').val();
	             }
            	if(($('#strStreet').val() ==null)||($('#strStreet').val()==""))
	             {
	             var strStreet ="";
	             }
               else
	             {
	                var strStreet = $('#strStreet').val();
	             }
            	
            	if(($('#strLocality').val() ==null)||($('#strLocality').val()==""))
	             {
	             var strLocality ="";
	             }
                 else
	             {
	                var strLocality = $('#strLocality').val();
	             }
            	if(($('#strPoName').val() ==null)||($('#strPoName').val()==""))
	             {
	             var strPoName ="";
	             }
                 else
	             {
	                var strPoName = $('#strPoName').val();
	             }
            	
            	if(($('#strVillage').val() ==null)||($('#strVillage').val()==""))
	             {
	             var strVillage ="";
	             }
                 else
	             {
	                var strVillage = $('#strVillage').val();
	             }
            	if(($('#strSubdist').val() ==null)||($('#strSubdist').val()==""))
	             {
	             var strSubdist ="";
	             }
                else
	             {
	                var strSubdist = $('#strSubdist').val();
	             }
            	
            	if(($('#strDistrict').val() ==null)||($('#strDistrict').val()==""))
	             {
	             var strDistrict ="";
	             }
                else
	             {
	                var strDistrict = $('#strDistrict').val();
	             }
            	
            	if(($('#strState').val() ==null)||($('#strState').val()==""))
	             {
	             var strState ="";
	             }
               else
	             {
	                var strState = $('#strState').val();
	             }
            	if(($('#strPincode').val() ==null)||($('#strPincode').val()==""))
	             {
	             var strPincode ="";
	             }
               else
	             {
	                var strPincode = $('#strPincode').val();
	             }
           	
            	var chkConsent = $('#chkConsent').is(":checked");
            	var consent=0
            	if(chkConsent ==true)
            		{
            		  consent = 1;
            		}
            	
            	$(document).ready(function () {
            	$.ajax({
            		   type : "POST",
            		   url: "<c:url value="/processAuthentication.html" />",
            		   processData: false,
            		   data:"aadhaar="+encodeURIComponent(labelaadhar_input)+"&name="+encodeURIComponent(name)+"&name_match="+encodeURIComponent(name_match)+"&name_matchingvalue="+encodeURIComponent(name_matchingvalue)+"&gender="+encodeURIComponent(gender)+"&year="+year+"&month="+month+"&date="+date+"&strAddressValue="+encodeURIComponent(strAddressValue)+"&strPfaMatched="+encodeURIComponent(strPfaMatched)+"&strAddressMatchvalue="+encodeURIComponent(strAddressMatchvalue)+"&strCareOf="+encodeURIComponent(strCareOf)+"&strBuilding="+encodeURIComponent(strBuilding)+"&strLandmark="+encodeURIComponent(strLandmark)+"&strBuilding="+encodeURIComponent(strBuilding)+"&strStreet="+encodeURIComponent(strStreet)+"&strLocality="+encodeURIComponent(strLocality)+"&strPoName="+encodeURIComponent(strPoName)+"&strVillage="+encodeURIComponent(strVillage)+"&strSubdist="+encodeURIComponent(strSubdist)+"&strDistrict="+encodeURIComponent(strDistrict)+"&strState="+encodeURIComponent(strState)+"&strPincode="+encodeURIComponent(strPincode)+"&consent="+encodeURIComponent(consent)+"&email="+encodeURIComponent(email)+"&mobileno="+encodeURIComponent(mobileno),
            		   beforeSend : function() {
              			  
                           $('#modal').css("display", "block");
                           $('#fade').css("display", "block");
                          },
                          
                          success : function(data) {
                            
                        	  var finaldata = JSON.parse(data);
                        	 
                        	  var resultnameh="";resultgenderh="";resultmailh="";resultmobilenoh="";resultdobh="";addressvalueh="";resultcareofh="";resultbuldingh="";resultlandmarkh="";resultstreeth="";resultlocalityh="";resultpoh="";resultvtch="";resultsubdisth="";resultdisth="";resultstateh="";resultpincodeh="";
                        	  var resultname="";var resultemail="";var resultmobileno="";resultgender="";resultdob="";addressvalue="";resultcareof="";resultbulding="";resultlandmark="";resultstreet="";resultlocality="";resultpo="";resultvtc="";resultsubdist="";resultdist="";resultstate="";resultpincode="";
                        	  
                        	  var demoresultlisttable = '<table class="gridtable"><tbody>';
                        	
                        	  var topaadhaarh='<tr><th>AADHAAR NUMBER</th>';
                        
                        	  if(finaldata.name!="")
                    		  {
                        		  resultnameh ='<th>NAME</th>';
                    		  }
                    	      if(finaldata.dob !="")
                    	    	{
                    	    	  resultdobh ='<th>DOB</th>';
                    	    	}
                    	     if(finaldata.gender !="")
                    	    	{
                    	    	 resultgenderh ='<th>GENDER</th>';
                    	    	}
                    	    
                    	     if(finaldata.email !="")
               	    	     {
                  	    	
                    	    	 resultmailh ='<th>EMAIL</th>';
               	    	     }
                    	       
                    	     if(finaldata.mobileno !="")
                 	    	   {
                    	    	
                 	    	     resultmobilenoh ='<th>MOBILENUMBER</th>';
                 	    	   }
                 	     
                    	     
                    	      if(finaldata.strAddressValue !="")
                	    	    {
                    	    	  addressvalueh ='<th>FULL ADDRESS</th>';
                	    	     }   
                      	    if(finaldata.strCareOf !="")
                  	    	 {
                      	        	resultcareofh ='<th>CARE OF</th>';
                  	    	 }
                      	    if(finaldata.strBuilding !="")
                  	    	 {
                      	        	resultbuldingh ='<th>BUILDING</th>';
                  	    	 }
                      	    
                      	    if(finaldata.strLandmark !="")
                  	    	{
                      	    	resultlandmarkh ='<th>LANDMARK</th>';
                  	    	}
                      	    if(finaldata.strStreet !="")
                  	    	{
                      	    	resultstreeth ='<th>STREET</th>';
                  	    	}
                      	    if(finaldata.strLocality !="")
                  	    	{
                      	    	resultlocalityh ='<th>LOCALITY</th>';
                  	    	}
                        	  if(finaldata.strPoName !="")
                  	    	   {
                      		     resultpoh ='<th>POST OFFICE</th>';
                  	    	   }
                      	     if(finaldata.strVillage !="")
                  	    	   {
                      	    	resultvtch ='<th>VTC</th>';
                  	    	   }
                      	     
                      	   if(finaldata.strSubdist !="")
               	    	       {
                      		    resultsubdisth ='<th>SUBDIST</th>';
               	    	       }
                   	       if(finaldata.strDistrict !="")
               	    	       {
                   		        resultdisth ='<th>DISTRICT</th>';
               	    	       }
                   	       if(finaldata.strState !="")
               	    	      {
                   	    	resultstateh ='<th>STATE</th>';
               	    	      }
                   	       if(finaldata.strPincode !="")
               	    	      {
                   	    	resultpincodeh ='<th>PINCODE</th>';
               	    	      }
                   	  
                   	   
                      	    var resultstatush ='<th>STATUS </th></tr>'; 
                      	    resultrow=topaadhaarh+resultnameh+resultgenderh+resultdobh+resultmobilenoh+resultmailh+addressvalueh+resultcareofh+resultbuldingh+resultlandmarkh+resultstreeth+resultlocalityh+resultpoh+resultvtch+resultsubdisth+resultdisth+resultstateh+resultpincodeh+resultstatush;
                      	      
                        	var resultadhaar ='<tr><td>'+finaldata.aadhaarnumber+'</td>'; 
                        		
                        	  if(finaldata.name!="")
                    		  {
                        		  resultname ='<td>'+finaldata.name+'</td>';
                    		  }
                    	     if(finaldata.dob !="")
                    	    	{
                    	    	 resultdob ='<td>'+finaldata.dob+'</td>';
                    	    	}
                    	    if(finaldata.gender !="")
                    	    	{
                    	    	resultgender ='<td>'+finaldata.gender+'</td>';
                    	    	}
                    	    if(finaldata.email !="")
                	    	{
                    	    	resultemail ='<td>'+finaldata.email+'</td>';
                	    	}
                    	    if(finaldata.mobileno !="")
                	    	{
                	    	resultmobileno ='<td>'+finaldata.mobileno+'</td>';
                	    	}
                    	    if(finaldata.strAddressValue !="")
                	    	{
                    	    	addressvalue ='<td>'+finaldata.strAddressValue+'</td>';
                	    	}
                        	
                            if(finaldata.strCareOf !="")
                   	    	    {
                        	    resultcareof ='<td>'+finaldata.strCareOf+'</td>';
                   	    	    }
                       	    if(finaldata.strBuilding !="")
                   	    	   {
                       		   resultbulding ='<td>'+finaldata.strBuilding+'</td>';
                   	    	   }
                       	    if(finaldata.strLandmark !="")
                   	    	   {
                       		    resultlandmark ='<td>'+finaldata.strLandmark+'</td>';
                   	    	   }
                       	     if(finaldata.strStreet !="")
                   	    	   {
                       		    resultstreet ='<td>'+finaldata.strStreet+'</td>';
                   	    	   }
                       	     if(finaldata.strLocality !="")
                   	    	   {
                       	    	resultlocality ='<td>'+finaldata.strLocality+'</td>';
                   	    	   }
                       	    if(finaldata.strPoName !="")
                   	    	{
                       	    	resultpo ='<td>'+finaldata.strPoName+'</td>';
                       	    	
                   	    	}
                       	   if(finaldata.strVillage !="")
                   	    	{
                       		    resultvtc ='<td>'+finaldata.strVillage+'</td>';
                       	    	
                   	    	}
                       	   if(finaldata.strSubdist !="")
                   	    	{
                       		 resultsubdist ='<td>'+finaldata.strSubdist+'</td>';
                   	    	}
                       	    if(finaldata.strDistrict !="")
                   	    	{
                       	    	  resultdist ='<td>'+finaldata.strDistrict+'</td>';
                   	    	}
                       	   if(finaldata.strState !="")
                   	    	{
                       		    resultstate ='<td>'+finaldata.strState+'</td>';
                   	    	}
                       	  if(finaldata.strPincode !="")
                   	    	{
                       		    resultpincode ='<td>'+finaldata.strPincode+'</td>';
                   	    	}
                        	  
                        
                      	     var resultstatus='<td>'+finaldata.message+'</td></tr>';
                      	     resultrow1=resultadhaar+resultname+resultgender+resultdob+resultmobileno+resultemail+addressvalue+resultcareof+resultbulding+resultlandmark+resultstreet+resultlocality+resultpo+resultvtc+resultsubdist+resultdist+resultstate+resultpincode+resultstatus;
							 var demoresultlisttableend = '</tbody></table>';
                        	  
                        	  
                        	  var demoresultlist = $('<div class="outPut"  style="clear: both;padding-top: 25px;padding-bottom: 40px;">').html(demoresultlisttable+resultrow+resultrow1+demoresultlisttableend);
          				      demo_result_data.append(demoresultlist);
                        	  
                        	  $('#labelaadhar_input').val("");
                        	  $('#gender').val("");
                        	  $('[name=month]').val("");
                        	  $('[name=date]').val("");
                        	  $('[name=year]').val("");
                        	  $('#name').val("");
                        	  $('#mobileno').val("");
                        	  $('#email').val("");
                        	  $('#strAddressValue').val("");
                        	  $('#strBuilding').val("");
                        	  $('#strBuilding').val("");
                        	  $('#strCareOf').val("");
                        	  $('#strDistrict').val("");
                        	  $('#strLandmark').val("");
                        	  $('#strLocality').val("");
                        	  $('#strPincode').val("");
                        	  $('#strPoName').val("");
                        	  $('#strState').val("");
                        	  $('#strStreet').val("");
                        	  $('#strSubdist').val("");
                        	  $('#strVillage').val("");
                        	  
                        	  
                        	  $('#modal').css("display", "none");
                              $('#fade').css("display", "none");
                          },
                          error : function(e) {
                 				console.log("ERROR: ", e);
                 				display(e);
                 			}
            		   
            		  });
            	});
            }
        
         </script>
         
        
  
  </div>



 <%@ include file="template/footer.jsp" %>