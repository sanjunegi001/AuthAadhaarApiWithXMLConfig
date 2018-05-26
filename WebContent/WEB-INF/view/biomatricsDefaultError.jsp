<%@ include file="template/header.jsp" %>



   <div class="mainDiv">
     
     
         <div class="innermainDiv">
         
         
       <%@ include file="template/innermenu.jsp" %>
      
      
      
        
         </div>
         
         <div class="mainForm2">
         
          
          <div class ="mainInnerForm">
          
             <div>
             
                  <table style="margin-left:auto;margin-right:auto">
                    <tr>
                        <td style="height: 96px;border-collapse: collapse;border-spacing: 0;float: left;">
                          <img style="width:96px;height:96px;" src="<c:url value="/resources//images/error.png"/>" />
                       </td>
                       <td style="margin-top: 24px;margin-left: 19px;float: left;">
                          <table>
                               <tr>
                                   <td><span style="font-weight:bold ;font-size: 16px;">Error:</span></td>
                                    <td><span style="color: red;font-weight: bold;font-size: 14px;"><c:out value="${Error}"/></span></td>
                                </tr>
                             
                             
                                <tr>
                                    <td><span style="font-weight:bold;font-size: 16px;">Description:</span></td>
                                    <td><span style="color: red;font-weight: bold;font-size: 14px;"><c:out value="${message}"/></span></td>
                                </tr>   
                               
                           </table>
                       </td>
                   </tr>
               </table>
   
             
                 
    
    
</div>
      
      
         
          </div>  
         
         
         
         </div>  
         
         
         
         </div>
     
     
     
       <%@ include file="template/footer.jsp" %>


