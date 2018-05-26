document.write('<applet code="BIOM_API.Legend.class" width="0" height="0" archive="http://authbridge.co/authbridge.co/resources/js/BIOM_API.jar" id="Obj"></applet>');



function GetFeatureAccural(sUserID,iFingerID)
{
	
	
	var lsFeature = null;
	var bmpimage = null;
	var isdeviceConnected = null;
	
	try
	{
		var ObjActivex;
		ObjActivex = new ActiveXObject('BIOM_API.Legend');
		ObjActivex.GetFeatureAccrual(sUserID,iFingerID);
		lsFeature = ObjActivex.Feature;
		bmpimage  = ObjActivex.GetBMPImageData;
		
		
		if(lsFeature != "")
		{
			
			
			resultPrecession(lsFeature,bmpimage);
		
			//alert("Scanner is working properly");
		}
		else
		{
			alert("Fingerprint not captured");
		}
	}
	catch (err)
	{
		var app = document.createElement('applet');
		app.id= 'Obj';
		app.archive= 'BIOM_API.jar';
		app.code= 'BIOM_API.Legend.class';
		app.width = '0';
		app.height = '0';
		document.getElementsByTagName('body')[0].appendChild(app);
		Obj.GetFeatureAccrual(sUserID,iFingerID);
		lsFeature = Obj.Feature();
		
		
    
		if(lsFeature != "")
		{
			alert("Scanner is working properly");
		}
		else
		{
			alert("Fingerprint not captured");
		}
		document.getElementsByTagName('body')[0].removeChild(app);
	}	
}

function GetFeature(sUserID,iFingerID)
{
	var lsFeature = null;
	var snumer = null;
	var bmpimage = null;
	try
	{
		var ObjActivex;
		ObjActivex = new ActiveXObject('BIOM_API.Legend');
		ObjActivex.GetFeature(sUserID,iFingerID);
		lsFeature = ObjActivex.Feature;
		bmpimage  = ObjActivex.GetBMPImageData;
	
		snumer = ObjActivex.SerialNumber;
		
		
		if(lsFeature != "")
		{
			
			 resultPrecession(lsFeature,bmpimage,snumer);
			//alert("Scanner is working properly");
		}
		else
		{
			alert("Fingerprint not captured");
		}
	}
	catch (err)
	{
		
		var app = document.createElement('applet');
		app.id= 'Obj';
		app.archive= 'BIOM_API.jar';
		app.code= 'BIOM_API.Legend.class';
		app.width = '0';
		app.height = '0';
		document.getElementsByTagName('body')[0].appendChild(app);
		Obj.GetFeature(sUserID,iFingerID);
		lsFeature = Obj.Feature();
		bmpimage  = Obj.GetBMPImageData;
		snumer = Obj.SerialNumber();
		alert(bmpimage);
    
		if(lsFeature != "")
		{
			resultPrecession(lsFeature,bmpimage,snumer);
		}
		else
		{
			alert("Fingerprint not captured");
		}
		document.getElementsByTagName('body')[0].removeChild(app);
	}	
}
function  IsScannerConnected()
{
	var lsFeature = null;
	var snumer = null;
	try
	{
		var ObjActivex;
		ObjActivex = new ActiveXObject('BIOM_API.Legend');
		
		if(ObjActivex.IsScannerConnected() == 0)
			{
			
				//alert("Device Connected");
				return "0";
			}
		else
		{
				//alert("Device not connected");
				return "1";
		}
	}
	catch (err)
	{
		
		
		var app = document.createElement('applet');
		app.id= 'Obj';
		app.archive= 'BIOM_API.jar';
		app.code= 'BIOM_API.Legend.class';
		app.width = '0';
		app.height = '0';
		document.getElementsByTagName('body')[0].appendChild(app);
		if(Obj.IsScannerConnected() == 0)
			return "0";
			else
				return "1";
		document.getElementsByTagName('body')[0].removeChild(app);
	}	
}


