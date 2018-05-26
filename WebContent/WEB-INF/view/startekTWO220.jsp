<%@ include file="template/header.jsp" %>



<div id="results"><!-- Results are displayed here --></div>
        <div id="fade"></div>
        <div id="modal">
            <img id="loader" src="<c:url value="/resources/images/loading.gif" />" />
        </div>

<script type="text/javascript">

function isTRMChecked() {
	return $('#chkConsent').is(':checked');	}


function EnableDisableTermsButton()
{
	
	
	 if (isTRMChecked()) {
	    	
	    	document.getElementById('btnCapture').disabled = false;
	    	
	    }
	    else {
	    	
	    	
	          document.getElementById('btnCapture').disabled = true;
	        
	    }
	
}


</script>



   <div class="mainDiv">
     
     
         <div class="innermainDiv">
            
            
            
           <%@ include file="template/innermenu.jsp" %>
            
         
         <div class="mainForm2">
         
          
          <div class ="mainInnerForm">
          
          
          <c:url var="bioauthcapForm" value="processstartekFm220.html" />
          
          
           <form:form id="bioauthcapForm" name="bioauthcapForm"  modelAttribute="biocapuser" action="${bioauthcapForm}">
         
            <div style="width:100%;height:50px; text-align:center;">
                        <span style="font-family:Arial, Helvetica, sans-serif; color:#000000; font-size:14px;"> Aadhaar Number : </span>
                        <input class="roundedcontrol" type="text" id="txtAadhaarNo" name="txtAadhaarNo" placeholder="Enter Aadhaar number" readonly="readonly" value="<c:out value="${sessionanumber}"/>">
                        &nbsp;&nbsp;<span id="errIndicator" style="color:red"></span>
             
                  <input type="hidden" id="deviceType" name="deviceType" value="<c:out value="${devicetype}"/>"/>
                  <input type="hidden" id="veritype" name ="veritype" value="${fingertype}">
                  <input type="hidden" id="deviceValue1" name="deviceValue1" value=""/>
                  <input type="hidden" id="deviceValue2" name="deviceValue2" value=""/>
             
             </div>
             
             <div style="width:100%; height:50px; text-align:left; font-family:Verdana, Arial, Helvetica, sans-serif; color:#333333; font-size:13px;">
                        <table>
                            <tbody>
                                <tr>
                                    <td valign="top">
                                        <input type="checkbox" id="chkConsent" onclick="EnableDisableTermsButton()">
                                    </td>
                                    <td valign="top" style="padding-left:5px" class="">
                                        <span class="" contenteditable="false">I hereby state that I have no objection in authenticating myself with Aadhaar based authentication system and consent to provide my Aadhaar Number, Biometric for Aadhaar based know your customer.</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table><br>
              </div>
              
             <div style="width:100%; margin-top:10px;text-align:center; font-family:Arial, Helvetica, sans-serif;">
                        <table>
                            <tbody><tr>
                                <td>
                                
                                    <span style="font-size: 12px;vertical-align:middle; color:#000866;font-weight:bold" id="deviceUsed">Using device :<c:out value="${devicetype}"/></span>
                                </td>
                            </tr>
                        </tbody></table>
               </div>
         
              <div style="width:100%; height:50px; margin-top:10px;text-align:center; font-family:Arial, Helvetica, sans-serif; color:#333333; font-size:34px;">
                        <table style="margin-left: auto;margin-right: auto;">
                            <tbody>
                                <tr>
                                    <td>
                                        <strong>
                                            <span id="deviceNameDescription"></span>
                                        </strong>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                 </div>
           
                <div style="width:100%; height:50px; margin-top:10px;text-align:center; font-family:Arial, Helvetica, sans-serif; color:#333333; font-size:34px;">
                        <table style="margin-left: auto;margin-right: auto;">
                            <tbody>
                                <tr>
                                    <td>
                                        <strong>
                                            <span id="deviceNameDescription">Please scan your Fingerprint</span>
                                        </strong>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
         
         
         <div style="width:100%">
                        <table style="margin-left: auto;margin-right: auto;text-align:center;border: 1px solid #000;background-color: #fff;width: 166px;">
                            <tbody>
                                <tr>
                                    <td style="height:240px">
                                        <div id="appletTd" style="position:relative;height:240px;">
                                        
                                          <c:choose>
                                          
                                                <c:when test="${not empty lists}">
                                               
                                                  
                                                </c:when>
                                                <c:otherwise> 
                                                      <p>
                                                      
                                                       <img src="<c:url value="/resources/images/finger_image.jpg"/>" id="realimage" style="height: 240px;width: 171px;">
                                                      
                                                      </p>
                                                </c:otherwise>
                                         </c:choose>    

                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        
                        <table style="margin-left: auto;margin-right: auto;text-align:center">
                            <tbody>
                                <tr>
                                    <td>
                                        <span style="color: #32E613;font-weight: bold;font-size: 13px;" id="deviceStatus">Fingerprint Scanner Initialized Successfully</span>
                                    </td>
                                </tr>
                                
                                 <tr>
                                    <td>
                                        <span class="blink_me" style="color:red;" id="error"></span>
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <div style="margin-top:5px">
                                            <input id="btnCapture" type="button" onclick ="captureFP()" value="Start Capture" disabled="disabled"/>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
      
         </form:form>
      
         </div>  
      
         </div>  
        </div>
     
     
      <%@ include file="template/footer.jsp" %>


<script type="text/javascript">


function Jsonp_Callback(json) {
	if (json.Error != null) {
		alert(json.Message);
	}
}

function crossDomainAjax (url, callback) {
	// IE8 & 9 only Cross domain JSON GET request
	if ('XDomainRequest' in window && window.XDomainRequest !== null) {
		var xdr = new XDomainRequest(); // Use Microsoft XDR
		xdr.open('get', url);
		xdr.onload = function () {
			var dom  = new ActiveXObject('Microsoft.XMLDOM'),
				JSON = $.parseJSON(xdr.responseText);                                                             
			dom.async = false;
			if (JSON == null || typeof (JSON) == 'undefined') {
				JSON = $.parseJSON(data.firstChild.textContent);
			}
			callback(JSON);
		};
		xdr.onerror = function() {
			_result = false; 
		};
		xdr.send();
	}
	// IE7 doesn't support cross domain request at all! :( :)
	// jQuery AJAX for other browsers         
	else {
		$.support.cors = true;
		$.ajax({
			url: url,
			crossDomain: true,
			contentType: 'text/plain',
			cache: false,
			dataType: 'jsonp',
			type: 'GET',
			async: false, // must be set to false
			jsonpCallback: "Jsonp_Callback",
			success: function (data, success) {
				callback(data);
			},
			error: function(jqXHR, exception) {
				if (jqXHR.status === 0) {
					alert('Not connect.\n Verify Network.');
				} else if (jqXHR.status == 404) {
					alert('Requested page not found. [404]');
				} else if (jqXHR.status == 500) {
					alert('Internal Server Error [500].');
				} else if (exception === 'parsererror') {
					alert('Requested JSON parse failed.');
				} else if (exception === 'timeout') {
					alert('Time out error.');
				} else if (exception === 'abort') {
					alert('Ajax request aborted.');
				} else {
					alert('Uncaught Error.\n' + jqXHR.responseText);
				}
			}
		});
	}
}

function captureFP() {
	
	
	var devicetype     = $('#deviceType').val();
	
	
	
	if(devicetype == "STARTEK_FM220")
		{
		
		
		    crossDomainAjax("http://localhost:8090/FM220/gettmpl?callback=?",
				  function (result) {
					SuccessFunc(result);
				  });
		
		}
	else if( devicetype =="MORPHO_1300E3")
	{

	   	var url = "http://127.0.0.1:11100/capture";
        var PIDOPTS='<PidOptions ver=\"1.0\">'+'<Opts fCount=\"2\" fType=\"0\" iCount=\"\" iType=\"\" pCount=\"\" pType=\"\" format=\"0\" pidVer=\"2.0\" timeout=\"10000\" otp=\"\" wadh=\"\" posh=\"\"/>'+'</PidOptions>';
		var xhr;
	    var ua = window.navigator.userAgent;
		var msie = ua.indexOf("MSIE ");
		
		 if (msie > 0 || !!navigator.userAgent.match(/Trident.*rv\:11\./)) // If Internet Explorer, return version number
		{
			
						//IE browser
						xhr = new ActiveXObject("Microsoft.XMLHTTP");
		} else {
						//other browser
						
						xhr = new XMLHttpRequest();
	    }
		        
				  xhr.open('CAPTURE', url, true);
				  xhr.setRequestHeader("Content-Type","text/xml");
				  xhr.setRequestHeader("Accept","text/xml");
								  
		        xhr.onreadystatechange = function () {
		        	 //alert(xhr.responseText);  
		     if (xhr.readyState == 4){
		    	 
		    	  var status = xhr.status;
		    	  if (status == 200) {
		    		
		    		 var xmlDoc = jQuery.parseXML(xhr.responseText),
                                    $xml = $(xmlDoc),
                                    $title = $xml.find("Resp");
		    		 var errorCode = $title.attr("errCode");
		    		 
		    		 if ($.trim(errorCode) == 720) {
		    			 alert("Biometric device is not ready");
		    		 }
		    		 else{
		    			 
		    			// alert(xhr.responseText);   
		    			 document.getElementById("realimage").src = "data:image/bmp;base64," + xhr.responseText; 
		    			
		    			 bioTwoProcessAction(xhr.responseText);
		    			 
		    		 }
		    		 
		    		
		    	  }else{
		    		  
		    		  alert("Biometric device is not attached with your system");
		    	  }
		            
		            
				}

		     
				
		     xhr.onerror = function () {
		         alert("Check If Morpho Service/Utility is Running");
		    }
		        };
		       
		        xhr.send(PIDOPTS);	
		        
		        
		        
	 
	  
		        
	}
	
	
	
	

}



function jsonp(url, callback) {
	// create a unique id
	var id = "_" + (new Date()).getTime();

	// create a global callback handler
	window[id] = function (result) {
			// forward the call to specified handler                                       
			if (callback)
				callback(result);
						
			// clean up: remove script and id
			var sc = document.getElementById(id);
			sc.parentNode.removeChild(sc);
			window[id] = null;
		}

	url = url.replace("callback=?", "callback=" + id);
				
	// create script tag that loads the 'JSONP script' 
	// and executes it calling window[id] function                
	var script = document.createElement("script");
	script.setAttribute("id", id);
	script.setAttribute("src", url);
	script.onerror=ErrorFunc;
	script.setAttribute("type", "text/javascript");
	document.body.appendChild(script);
}


function SuccessFunc(result)
{
	  if(result.errorCode ==0)
		{
		  
		  
		  
		  if (result != null && result.bMPBase64.length > 0) {
              document.getElementById("realimage").src = "data:image/bmp;base64," + result.bMPBase64;
              
              
          }
		    
		  //alert(result.serialNumber);
		   
		     bioProcessAction(result.templateBase64,result.serialNumber,"ACP220STK");
		    //bioProcessAction(result.templateBase64);
		     
		}
	  else
      {
		  alert("Fingerprint Capture ErrorCode " + result.errorCode + "Desc :-"+result.status);
      }
	
	
}
  
  
  
function bioProcessActionDemo(bmpimagecode,udc,fdc)
{
	
	if(bmpimagecode)
		{
		   window.location = "startekTWO220Final.html?type="+bmpimagecode;
		}
	
	
	
}
  
  
function bioTwoProcessAction(bmpimagecode){

	
	if(bmpimagecode.length>0)
		{
		
		
		var biotype= $('#veritype').val();
		var aadhaarno=$('#txtAadhaarNo').val();
		
		
	if(biotype=="FMR")
		{
		
		 
         $.ajax({
			
			
			type : "POST",
			//data:"baseimagecode="+bmpimagecode+"&udccode="+udc+"&fdccode=ACP220STK",
			 url : "<c:url value="/startekAuthentication.html" />",
			 //url : "<c:url value="/biomatricsauth.html" />",
			processData: false,
			data:"baseimagecode="+bmpimagecode+"&udccode="+udc+"&fdccode="+fdc,
			beforeSend : function() {
				
                $('#modal').css("display", "block");
                $('#fade').css("display", "block");
               },
			success : function(data) {
				var finaldata = JSON.parse(data);
				//$('#preloader').removeClass('active');
				if(finaldata.error=="0"){
				document.getElementById("error").textContent=finaldata.message;
				}
				//window.location.replace(data);
			},
			error : function(e) {
				console.log("ERROR: ", e);
				display(e);
			}
			
			
			
		});
		
		}
	 else if(biotype=="BIOFMR")
		 {
		 document.getElementById("error").textContent="";
		 
		 $.ajax({
				
				
				type : "POST",
				
				 url : "<c:url value="/startekbioAuthentication.html" />",
				 //url : "<c:url value="/biomatricsauth.html" />",
				processData: false,
				
				data:"baseimagecode="+encodeURIComponent(bmpimagecode)+"&aadhaarnumber="+aadhaarno,
				beforeSend : function() {
					
	                $('#modal').css("display", "block");
	                $('#fade').css("display", "block");
	               }, 
				success : function(data) {
					
					 if(data.indexOf(".html") > -1){
						 
						 window.location.replace(data);
					 }
					 else{
						 
						 var finaldata = JSON.parse(data);
						 $('#modal').css("display", "none");
			             $('#fade').css("display", "none");
						 document.getElementById("error").textContent=finaldata.message;
						 
					 }
					
				},
				error : function(e) {
					console.log("ERROR: ", e);
					display(e);
				}
				
				
				
			});
			
		 
		 
		 }else if(biotype=="TWOFINGER")
				 {
			 document.getElementById("error").textContent="";
			 
			 
			 
			 $.ajax({
					
					
					type : "POST",
					
					 url : "<c:url value="/twofingerAuthentication.html" />",
					 //url : "<c:url value="/biomatricsauth.html" />",
					processData: false,
					
					data:"baseimagecode="+encodeURIComponent(bmpimagecode)+"&aadhaarnumber="+aadhaarno,
					beforeSend : function() {
						
		                $('#modal').css("display", "block");
		                $('#fade').css("display", "block");
		               }, 
					success : function(data) {
						
						 if(data.indexOf(".html") > -1){
							 
							 window.location.replace(data);
						 }
						 else{
							 
							 var finaldata = JSON.parse(data);
							 $('#modal').css("display", "none");
				             $('#fade').css("display", "none");
							 document.getElementById("error").textContent=finaldata.message;
							 
						 }
						
					},
					error : function(e) {
						console.log("ERROR: ", e);
						display(e);
					}
					
					
					
				});
				
			 
			 
			 }
		
		
		
		
		}
	 else
		{
		    alert("Please Connect Device Properly");
		}
}  
  
  
  
function bioProcessAction(bmpimagecode,udc,fdc)
{
	
	if(bmpimagecode.length>0)
		{
		
		var biotype= $('#veritype').val();
		var secret = $('#secret').val();
		
		
	if(biotype=="FMR")
		{
		
		 
         $.ajax({
			
			
			type : "POST",
			//data:"baseimagecode="+bmpimagecode+"&udccode="+udc+"&fdccode=ACP220STK",
			 url : "<c:url value="/startekFTwoAuthentication.html" />",
			 //url : "<c:url value="/biomatricsauth.html" />",
			processData: false,
			data:"baseimagecode="+bmpimagecode+"&udccode="+udc+"&fdccode="+fdc,
			beforeSend : function() {
				
                $('#modal').css("display", "block");
                $('#fade').css("display", "block");
               },
			success : function(data) {
				//$('#preloader').removeClass('active');
				window.location.replace(data);
			},
			error : function(e) {
				console.log("ERROR: ", e);
				display(e);
			}
			
			
			
		});
		
		}
	 else if(biotype=="BIOFMR")
		 {
		 
		 $.ajax({
				
				
				type : "POST",
				
				 url : "<c:url value="/startekbioAuthentication.html" />",
				 //url : "<c:url value="/biomatricsauth.html" />",
				processData: false,
				data:"baseimagecode="+bmpimagecode+"&udccode="+udc+"&fdccode="+fdc,
				beforeSend : function() {
					
	                $('#modal').css("display", "block");
	                $('#fade').css("display", "block");
	               },
				success : function(data) {
					//$('#preloader').removeClass('active');
					window.location.replace(data);
				},
				error : function(e) {
					console.log("ERROR: ", e);
					display(e);
				}
				
				
				
			});
			
		 
		 
		 }else if(biotype=="TWOFINGER")
				 {
			 document.getElementById("error").textContent="";
			 
			 
			 
			 $.ajax({
					
					
					type : "POST",
					
					 url : "<c:url value="/twofingerAuthentication.html" />",
					 //url : "<c:url value="/biomatricsauth.html" />",
					processData: false,
					
					data:"baseimagecode="+encodeURIComponent(bmpimagecode)+"&aadhaarnumber="+aadhaarno,
					beforeSend : function() {
						
		                $('#modal').css("display", "block");
		                $('#fade').css("display", "block");
		               }, 
					success : function(data) {
						
						 if(data.indexOf(".html") > -1){
							 
							 window.location.replace(data);
						 }
						 else{
							 
							 var finaldata = JSON.parse(data);
							 $('#modal').css("display", "none");
				             $('#fade').css("display", "none");
							 document.getElementById("error").textContent=finaldata.message;
							 
						 }
						
					},
					error : function(e) {
						console.log("ERROR: ", e);
						display(e);
					}
					
					
					
				});
				
			 
			 
			 }
		
		
		
		
		}
	 else
		{
		    alert("Please Connect Device Properly");
		}
	
	
	
}


</script>




