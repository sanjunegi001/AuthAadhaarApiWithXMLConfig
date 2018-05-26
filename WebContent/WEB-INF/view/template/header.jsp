<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>

 <script src="<c:url value="/resources/js/respond.js" />"></script>
 <script src="<c:url value="/resources/js/jquery-1.10.2.min.js" />"></script>
 <script src="<c:url value="/resources/js/jquery-ui.min.js" />"></script>
 <script src="<c:url value="/resources/js/jquery.blockUI.js" />"></script>
 



 
 <script>
function blinker() {
    $('.blink_me').fadeOut(500);
    $('.blink_me').fadeIn(500);
}

setInterval(blinker, 1500);

</script>
  <link href="<c:url value="/resources/css/style.css" />" rel="stylesheet"> 
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>AUTHBRIDGE | AADHARCARD VERIFICATION</title>
</head>
<body>
