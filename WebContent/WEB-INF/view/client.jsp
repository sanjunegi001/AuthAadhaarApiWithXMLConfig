<%@ include file="template/header.jsp" %>


<div class="mainDiv">

   <div class="innermainDiv">
  

         
          <div id="fade"></div>
      
      <img src="" id="attendencerealimage">
     
        <div id="modal">
            <img id="loader" src="<c:url value="/resources/images/loading.gif" />" />
        </div>
      </img> 
         
         <div class="mainForm">
            
         
               

                  <form:form id="aadharForm1" name="myform1" modelAttribute="user" action="">
                  
                  
                     <div class="mainaadharForm">
                     
                        <div id="main_top_auth_aadhaar" style="margin-top: 39px;">
                          
                            <div id="main_aadhaar_number">
                                <lable style="font-weight: bold;font-size: 14px;">Aadhaar Number<span style="color:red">*</span></lable>
                                <input type="text" name="aadharnumber" id="labelaadhar_input" style="margin-left: 4px;width: 309px;border: 1px solid #ccc;height: 23px;border-radius: 5px; "></input>
                             
                             </div>
                        
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
										
										
											
												
										      </table>
										    
										    </div>
										    
										
								
										</div>	
											
										</div>
									
								</td>
                             </tr>
                           
                           
                           
                           </table>
                       
                       
                        
                       
                 
                       
                        </div>
                        
                        
                        <div id="main_bottom_auth_aadhaar">
                             
                              <div class="action_buttion" style="padding-top: 30px;width: 242px;margin: 0 auto;float: none;">
                   
                                  <div class="action_buttion_auth">
                      
                                   <input type="button" value="Authenticate" id="inneraction_buttion_auth" onclick="return hoemAuthentication()">
                        
                                 </div>
                                <div class="action_buttion_cancel">
                                      <input type="cancel" value="CANCEL" id="inneraction_buttion_cancel" >
                               </div>
                   
                        </div>
                             
                        
                        </div>
                     
                     
                     
                     
                     </div>
                   </form:form>
         
          </div>
          </div>
           
          <div id="demo-result-data"> 
           
          </div>
         
      <!-- <table class="gridtable"><tbody> 
      <tr><th>REQUEST XML</th><th>RESPONSE XML</th></tr>
      <tr><td>
      	<pre  style="white-space: pre-wrap; word-wrap:break-word; width:500px"  id="container1"></pre>
      </td>
      <td>
      <pre  style="white-space: pre-wrap; word-wrap:break-word; width:500px"  id="container"></pre>
      </td>
      </tr>
        </tbody>
     </table> -->
      
    
        
         
      
      
         
         
         <script type="text/javascript">
         
            function hoemAuthentication()
            {
            	var demo_result_data = $('#demo-result-data');
            	demo_result_data.empty();
            	 var labelaadhar_input = $('#labelaadhar_input').val();
            	 var name = $('#name').val();
            	$(document).ready(function () {
            	$.ajax({
            		   type : "POST",
            		   url: "<c:url value="/processAuthentication1.html" />",
            		   processData: false,
            		   data:"aadhaar="+encodeURIComponent(labelaadhar_input)+"&name="+encodeURIComponent(name),
            		   beforeSend : function() {
              			  
                           $('#modal').css("display", "block");
                           $('#fade').css("display", "block");
                          },
                          
                          success : function(data) {
                            
                        	  
                        	  var finaldata = JSON.parse(data);
                        	 
                       
                        	  var resultnameh="";resultgenderh="";resultmailh="";resultmobilenoh="";resultdobh="";addressvalueh="";resultcareofh="";resultbuldingh="";resultlandmarkh="";resultstreeth="";resultlocalityh="";resultpoh="";resultvtch="";resultsubdisth="";resultdisth="";resultstateh="";resultpincodeh="";
                        	  var resultname="";var resultemail="";var resultmobileno="";resultgender="";resultdob="";addressvalue="";resultcareof="";resultbulding="";resultlandmark="";resultstreet="";resultlocality="";resultpo="";resultvtc="";resultsubdist="";resultdist="";resultstate="";resultpincode="";
                        	  
                        	 // var demoresultlisttable = '<div class="outPut">';
                        	  
                        	  var  outputtablestart = '<table class="gridtable"><tbody>';
                        	
                        	  var outputheader='<tr><th>REQUEST XML</th><th>RESPONSE XML</th></tr>';
                        	  
                        	  var outputrequest='<tr><td><pre  style="white-space: pre-wrap; word-wrap:break-word; width:500px"  id="container1"></pre> </td>';
                        	  
                        	  var outputresponse='<td><pre  style="white-space: pre-wrap; word-wrap:break-word; width:500px"  id="container"></pre></td></tr>';
                        	  
                        	  var  outputtableend = '</tbody></table>';
                   	   	
                      	     
                      	
                      	     //var demo1='<tr><th>"Aadhaar"</th></tr>';
                      	     //var resultadhaar ="<tr><td>"+finaldata.aadhaarnumber+"</td></tr>";
                      	     
                      	   // var demo2='<tr><th>"Aadhaar Name"</th></tr>';
                    	     //var resultname ="<tr><td>"+finaldata.name+"</td></tr>";
                        	
                        	  //var demoresultlisttableleft = '<tr><th>"REQUEST XML"</th></tr>';
                        	   //resultgender="<tr><td>"+finaldata.rqxml+"</td></tr>";	
                        	  
                        
                        	  
                        	  
                        	//  var demoresultlisttableright = '<tr><th>"REPONSE XML"</th></tr>';
                        	 // resultdob="<tr><td>"+finaldata.rsxml+"</td></tr>";
                       	     
                        	  
                        	  
                        	 // var resultstatus=finaldata.message;
                      	    
                      	   //resultrow1=resultgender+resultdob+resultstatus;
                      	   
                      	// var demoresultlisttableend1 = '</tbody></table>';
							// var demoresultlisttableend = '</div>';
                        	 
                        	  
                        	  demoresultlist = $('<div class="outPut"  style="clear: both;padding-top: 25px;padding-bottom: 40px;">').html(outputtablestart+outputheader+outputrequest+outputresponse+outputtableend);
          				      demo_result_data.append(demoresultlist);
          				    
                        	  $('#labelaadhar_input').val("");
                        	  
                        	  $('#name').val("");
                        	  
                        	  $('#container1').text(finaldata.rqxml);
                        	  $('#container').text(finaldata.rsxml);
                        	  
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
         
        
  
 



 <%@ include file="template/footer.jsp" %>