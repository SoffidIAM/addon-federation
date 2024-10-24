var demo = false;

var createCredentialDefaultArgs = {
    publicKey: {
        // Relying Party (a.k.a. - Service):
        rp: {
            name: "Soffid IAM"
        },
        // User:
		authenticatorSelection: {requireResidentKey: false, userVerification: 'discouraged'},
        user: {
            id: new Uint8Array(16),
            name: "soffid",
            displayName: "Soffid user"
        },
        pubKeyCredParams: [{
            type: "public-key",
            alg: -7
        }],
        attestation: "direct"
    }
};


var publicKeyCredential = {
		publicKey: {
			challenge: base64toArray(fingerprintChallenge).buffer,
			rpId: document.location.hostname,
//			userVerification: "required",
		    allowCredentials: [{
//	            id: base64toArray("soffid").buffer,
		        type: 'public-key'
		    }]
		}
	};


var rawId = null;

function base64toArray(text) {
    var raw = window.atob(text),
	    n = raw.length,
	    a = new Uint8Array(new ArrayBuffer(n));
	for(var i = 0; i < n ; i++){
	    a[i] = raw.charCodeAt(i);
	}
	return a;
}

function arrayToBase64(array)
{
	var a = "";

	var b = new Uint8Array(array);
	for(var i = 0; i < b.byteLength ; i++){
	    a += String.fromCharCode(b[i]);
	}
	return window.btoa(a);
}


function registerCredential (cred) 
{
	fetch(fingerprintRegisterUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: "clientJSON="+encodeURIComponent( arrayToBase64(cred.response.clientDataJSON) )+
	      "&attestation="+encodeURIComponent( arrayToBase64(cred.response.attestationObject)) +
	    		  "&rawId="+encodeURIComponent( arrayToBase64(cred.rawId))
    }).then ( function (response) {
		    return response.json();
    }).then( function(data) {
	    if (data.status == 'success')
	    {
	    	var serial = data.serial;
	    	localStorage.setItem("soffid.credential.serial", serial);
	  	  	$("#fingerprintregister").fadeOut("slow");
	  	  	$("#fingerprintinprogress").fadeIn("slow");
			if (fingerprintRegister)
				window.close();
	    }
	    else
	    {
	    	alert("ERROR: "+data.cause);
	    }
	});
}

function validateCredential (cred) 
{
	try {
		document.getElementById("fp-clientJSON").value = arrayToBase64(cred.response.clientDataJSON) ;
		document.getElementById("fp-authenticatorData").value = arrayToBase64(cred.response.authenticatorData) ;
		document.getElementById("fp-signature").value = arrayToBase64(cred.response.signature) ;
		document.getElementById("fp-rawId").value = arrayToBase64(cred.rawId);
		document.getElementById("fp-serial").value = localStorage.getItem("soffid.credential.serial");
		document.getElementById("form-fingerprint").submit();
	} catch (error) {
		alert("Error: "+error);
	}
}


function fingerprintCreate() {
	// sample arguments for login
	var getCredentialDefaultArgs = {
	    publicKey: {
	        timeout: 60000,
	        // allowCredentials: [newCredential] // see below
	        challenge: base64toArray(fingerprintChallenge).buffer
	    },
	};

	createCredentialDefaultArgs.publicKey.challenge = base64toArray(fingerprintChallenge).buffer;
	// register / create a new credential
	navigator.credentials.create(createCredentialDefaultArgs)
	    .then(function (cred) {
	        rawId = arrayToBase64( cred.rawId );
	        localStorage.setItem("soffid.credential.id", rawId);
	        localStorage.removeItem("soffid.credential.serial");
	        localStorage.setItem("soffid.credential.enabled", "false");
	        registerCredential ( cred );
	    })
	    .catch(function (err)  {
	        alert ("ERROR"+ err);
			window.close();
	    });
}


function fingerprintSign() {
	if (demo)
		validateCredential( { response: {rawId: "aaa", signature:"aaa"}} );
	else
	{
		var ac = [];
		for (var i = 0; i < fingerprintRawIds.length; i++) {
			ac.push({type: 'public-key', id: base64toArray(fingerprintRawIds[i])});
		}
	    publicKeyCredential.publicKey.allowCredentials = ac;
		navigator.credentials.get(publicKeyCredential)	    
	    .then(function (assertion) {
	        validateCredential ( assertion );
	    })
	    .catch(function (err) {
	        alert("ERROR "+ err);
			window.location.reload();
	    });  
	}
}


function activateFingerprint () 
{
	var e1 = document.getElementById("fingerprintlogin");
	var e2 = document.getElementById("fingerprintregister");
    var rawId = localStorage.getItem("soffid.credential.id");
    var serial = localStorage.getItem("soffid.credential.serial");
    
	if ( fingerprintToRemove && fingerprintToRemove == serial)
    {
    	localStorage.removeItem("soffid.credential.id");
    	localStorage.removeItem("soffid.credential.serial");
    	serial = false;
    }
    if (fingerprintRegister) {
		fingerprintCreate();
	}
    else if (demo || rawId && serial)
    {
    	if (e1)
    		e1.style.display="block";
//		e2.style.display="block";
    }
	else if (window.PublicKeyCredential)
    {
    	if (e2)
    		e2.style.display="block";
    }
}

