// JavaScript Document

/* Acc?s directe a les conselleries per mitj? del men? superior */
function accesDirecte() {
	valorUrl = document.getElementById('llista').options[document.getElementById('llista').selectedIndex].value;
	if(valorUrl.indexOf('.html') != -1) {
		document.location = valorUrl;
	}
}

function mostrarInfoDoc(obj) {
	ventanaX = document.body.offsetHeight;
	obj.style.cursor = 'help';
	
	/*
		RAFA: MODIFICAMOS PARA QUE LA CAPA DE AYUDA ESTE ANTES
		if(document.all) info = obj.parentNode.nextSibling;
		else info = obj.parentNode.nextSibling.nextSibling;
	*/
	if(document.all) info = obj.parentNode.previousSibling;
	else info = obj.parentNode.previousSibling.previousSibling;
	
	posX = saberPosX(obj);
	posY = saberPosY(obj.parentNode);
	altura = obj.offsetHeight;
	info.style.display = 'block';
	alturaInfo = info.offsetHeight;
	if(ventanaX < (posY + alturaInfo)) {
		with (info) {
			style.top = posY - alturaInfo + 'px';
			style.left = posX + 'px';
		}
	} else {
		with (info) {
			style.top = posY + altura + 'px';
			style.left = posX + 'px';
		}
	}
	obj.onmouseout = function() { info.style.display = 'none'; };
}

// para conocer la posici?n X del enlace con respecto a la p?gina
function saberPosX(obj) {
	var curleft = 0;
	if (obj.offsetParent) {
		while (obj.offsetParent) {
			curleft += obj.offsetLeft
			obj = obj.offsetParent;
		}
	} else if (obj.x) {
		curleft += obj.x;
	}
	return curleft;
}
// para conocer la posici?n Y del enlace con respecto a la p?gina
function saberPosY(obj) {
	var curtop = 0;
	if (obj.offsetParent) {
		while (obj.offsetParent) {
			curtop += obj.offsetTop
			obj = obj.offsetParent;
		}
	} else if (obj.y) {
		curtop += obj.y;
	}
	return curtop;
}

// para acceder a los formularios o enviar info. Capa con un mensaje de espera.
/* version 1 - DESESTIMADA
function accediendoEnviando(obj) {
	capaEnv = document.getElementById('accEnv');
	capaIcosY = document.getElementById('iconografia').offsetHeight;
	if(document.getElementById('listadoFormularios') != 'undefined') capa = document.getElementById('listadoFormularios');
	posX = saberPosX(capa);
	posY = saberPosY(capa);
	capaY = capa.offsetHeight;
	capaEnv.style.display = 'block';
	if(capaIcosY > capaY) {
		capaEnv.style.height = capaIcosY/2 + 15 + 'px';
		capaEnv.style.paddingTop = capaIcosY/2 - 15 + 'px';
	} else {
		capaEnv.style.height = capaY/2 +15 + 'px';
		capaEnv.style.paddingTop = capaY/2 -15 + 'px';
	}
	with(capaEnv) {
		style.top = posY - 1 + 'px';
		style.left = posX + 'px';
		innerHTML = '<img src="imgs/enviando.gif" alt="Accediendo al formulario" /> Espere, por favor. Estamos accediendo al formulario...';
	}
}

*/

			function posicionOffset(obj,tipo) {
				if(obj != null) {
					var totalOffset = (tipo == "left") ? obj.offsetLeft : obj.offsetTop;
					var parentEl = obj.offsetParent;
					while (parentEl != null){
						totalOffset = (tipo == "left") ? totalOffset+parentEl.offsetLeft : totalOffset+parentEl.offsetTop;
						parentEl = parentEl.offsetParent;
					}
					return totalOffset;
				}
			}

			opacidad = 0;
			function fundidoMostrar(id) {
				obj = document.getElementById(id);
				if(opacidad < 40) {
					opacidad += 10;
					if(typeof obj.style.filter != 'undefined') {
						if(window.opera) obj.style.opacity = opacidad/100;
						else obj.style.filter = "alpha(opacity="+opacidad+")";
					} else {
						obj.style.opacity = opacidad/100;
					}
					tiempo = setTimeout('fundidoMostrar("'+id+'")', 50);
				} else {
					clearTimeout(tiempo);
					opacidad = 0;
				}
			}

function mostrarFondo() {
				if(document.getElementById('fondo') == null) {
					// creamos capa
					fondoC = document.createElement('div');
					fondoC.setAttribute('id','fondo');
					document.body.appendChild(fondoC);
				}
				// capturamos tamanyos
				ventanaX = document.documentElement.clientWidth;
				ventanaY = document.documentElement.offsetHeight;
				bodyY = document.body.offsetHeight;
				usuariY = document.documentElement.clientHeight;
				if(bodyY > ventanaY) ventanaY = bodyY;
				if(usuariY > ventanaY) ventanaY = usuariY;
				// solo para IE, escondemos todos los SELECT
				if(document.all) {
					selects = document.getElementsByTagName('select');
					for(i=0;i<selects.length;i++) selects[i].style.display = 'none';
				}
				// mostramos el fondo
				fondoDiv = document.getElementById('fondo');
				fondoDiv.style.display = 'block';
				if(document.all) fondoDiv.style.filter = "alpha(opacity=0)";
				else fondoDiv.style.opacity = 0;
				fondoDiv.style.width = ventanaX + 'px';
				fondoDiv.style.height = ventanaY + 'px';
				return ventanaX, ventanaY, usuariY;
			}
			
			function esconderFondo() {
				// solo para IE, mostramos todos los SELECT
				if(document.all) {
					selects = document.getElementsByTagName('select');
					for(i=0;i<selects.length;i++) selects[i].style.display = 'inline';
				}
				document.getElementById('fondo').style.display = 'none';
			}

// Version 2
function accediendoEnviando(mensaje) {
	
	contenido = mensaje;
	
	var capaIF = document.getElementById('capaInfoFondo');
	var capaI = document.getElementById('capaInfoForms');
	// tama?os de la ventana y la p?gina
	var scroller = document.documentElement.scrollTop;
	var ventanaX = document.documentElement.clientWidth;
	var ventanaY = document.documentElement.clientHeight;
	var capaY = document.getElementById('contenedor').offsetHeight;
	// la capa de fondo ocupa toda la p?gina
	with (capaIF) {
		if(ventanaY > capaY) style.height = ventanaY + 'px';
		else style.height = capaY + 'px';
		if(document.all) style.filter = "alpha(opacity=40)";
		else style.MozOpacity = 0.4;
		if(document.all) style.width = ventanaX + 'px';
		style.display = 'block';
	}
	// colocamos el texto adecuado
	capaI.innerHTML = contenido;
	// mostramos, miramos su tama?o y centramos la capaInfo con respecto a la ventana
	capaI.style.display = 'block';
	capaInfoX = capaI.offsetWidth;
	capaInfoY = capaI.offsetHeight;
	with (capaI) {
		style.left = parseInt((ventanaX-capaInfoX)/2) + 'px';
		if(document.all) style.top = parseInt(scroller+(ventanaY-capaInfoY)/2) + 'px';
		else style.top = parseInt((ventanaY-capaInfoY)/2) + 'px';
		if(!document.all) style.position = 'fixed';
		if(document.all) style.filter = "alpha(opacity=0)";
		else style.MozOpacity = 0;
	}
	// y mostramos la capa ayuda
	mostrarCapa();
}

function reposicionaCapa(){
	var scroller = (document.body.scrollTop) ? document.body.scrollTop : document.documentElement.scrollTop;
	var ventanaY = document.documentElement.clientHeight;
	if(document.getElementById('capaInfoForms') != 'undefined') var capaI = document.getElementById('capaInfoForms');
	capaInfoY = capaI.offsetHeight;
	capaI.style.top = parseInt(scroller+(ventanaY-capaInfoY)/2) + 'px';
}

opacidad = 0;
function mostrarCapa() {
	if(opacidad < 100) {
		opacidad += 20;
		if(document.all) document.getElementById('capaInfoForms').filters.alpha.opacity = opacidad;
		else document.getElementById('capaInfoForms').style.MozOpacity = opacidad/100;
		tiempo = setTimeout('mostrarCapa()', 50);
	} else {
		clearTimeout(tiempo);
		opacidad = 0;
	}
}

// capa de informaci?n. Puede ser: info, error, ok.
function mostrarInfo() {
	var capaI = document.getElementById('capaInfo');
	var capaIF = document.getElementById('capaInfoFondo');
	
	// tama?os de la ventana y la p?gina
	var ventanaX = document.documentElement.clientWidth;
	var ventanaY = document.documentElement.clientHeight;
	var capaY = document.getElementById('contenedor').offsetHeight;
	
	
	// la capa de fondo ocupa toda la p?gina	
	with (capaIF) {
		if(ventanaY > capaY) style.height = ventanaY + 'px';
		else style.height = capaY + 'px';
		if(document.all) style.filter = "alpha(opacity=30)";
		else style.MozOpacity = 0.3;
		if(document.all) style.width = ventanaX + 'px';
		style.display = 'block';
	}
	// OJO, descomentar si se quiere poder pulsar en cualquier parte de la pantalla
	//capaIF.onclick = cerrarInfo;	
	
	// mostramos, miramos su tama?o y centramos la capaInfo con respecto a la ventana
	capaI.style.display = 'block';
	capaInfoX = capaI.offsetWidth;
	capaInfoY = capaI.offsetHeight;
	with (capaI) {
		style.left = (ventanaX-capaInfoX)/2 + 'px';
		style.top = (ventanaY-capaInfoY)/2 + 'px';
	}
}
// esconder las capas info
function cerrarInfo() {
	document.getElementById('capaInfo').style.display = 'none';
	document.getElementById('capaInfoFondo').style.display = 'none';
}

// para mostrar la capa
function mostrarDocInfo(obj,capa) {
	capaInfo = document.getElementById(capa+'info'); // la capa info en cuesti?n
	posX = saberPosX(obj);
	posY = saberPosY(obj);
	altura = obj.offsetHeight;
	with (capaInfo) {
		style.top = posY + altura + 'px';
		style.left = posX + 'px';
		style.display = 'block';
	}
	document.getElementById(capa).onmouseout = esconderDocInfo; // cuando el rat?n se quite adi?s a la capa
	document.getElementById(capa).onblur = esconderDocInfo;
}

// para esconder la capa
function esconderDocInfo() {
	capaInfo.style.display = "none";
}

// Mostrar informaci?n iconograf?a
function icosMasInfo() {
	icos = document.getElementById('iconografia');
	spans = icos.getElementsByTagName('span');
	for(i=0; i<spans.length; i++) {
		if(spans[i].style.display == 'inline') spans[i].style.display = 'none';
		else  spans[i].style.display = 'inline';
	}
	if(icos.getElementsByTagName('span')[0].style.display == 'inline') document.getElementById('iconografiaMasInfo').innerHTML = '<bean:message key="iconografia.ocultarInfo"/>';
	else document.getElementById('iconografiaMasInfo').innerHTML = '<bean:message key="iconografia.masInfo"/>';
}


function ocultarAyudaAdmin() {
	var capaI = document.getElementById('contactoAdministrador');
	capaI.style.display = 'none';
	esconderFondo();
}

// Abre pantalla de ayuda
function mostrarAyudaAdmin() {
	
	mostrarFondo();
	fundidoMostrar('fondo');

	var capaI = document.getElementById('contactoAdministrador');

	// tama?os de la ventana y la p?gina
	var ventanaX = document.documentElement.clientWidth;
	var ventanaY = document.documentElement.clientHeight;
	var capaY = document.documentElement.offsetHeight;
	
	// mostramos, miramos su tama?o y centramos la capaInfo con respecto a la ventana
	capaI.style.display = 'block';
	capaInfoX = capaI.offsetWidth;
	capaInfoY = capaI.offsetHeight;
	with (capaI) {
		style.left = (ventanaX-capaInfoX)/2 + 'px';
		style.top = (ventanaY-capaInfoY)/2 + 'px';
	}
	
	if(window.XMLHttpRequest) {
		capaI.style.position = 'fixed';
		capaI.style.top = (usuariY - capaInfoY)/2 + 'px';
	} else {
		ventanaScrollY = document.documentElement.scrollTop;
		capaI.style.top = (usuariY - capaInfoY)/2 + ventanaScrollY + 'px';
	}
	
	
}

function cargarCertificado()
{
	var applet = whichApplet();
	res = applet.inicializarDispositivo( contentType );
	if (!res) 
	{
		alert(applet.getLastError());
		return;
	}
}

function whichApplet ()
{
	var _info = navigator.userAgent;
	if (_info.indexOf("MSIE") > 0 && _info.indexOf("Win") > 0 &&
        _info.indexOf("Windows 3.1") < 0) {
        return document.appfirma;
	} else {
        return document.appfirma2;
	}
}

function URLEncode(text)
{
	// The Javascript escape and unescape functions do not correspond
	// with what browsers actually do...
	var SAFECHARS = "0123456789" +					// Numeric
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +	// Alphabetic
					"abcdefghijklmnopqrstuvwxyz" +
					"-_.!~*'()";					// RFC2396 Mark characters
	var HEX = "0123456789ABCDEF";

	var plaintext = text;
	var encoded = "";
	for (var i = 0; i < plaintext.length; i++ ) {
		var ch = plaintext.charAt(i);
	    if (ch == " ") {
		    encoded += "+";				// x-www-urlencoded, rather than %20
		} else if (SAFECHARS.indexOf(ch) != -1) {
		    encoded += ch;
		} else {
		    var charCode = ch.charCodeAt(0);
			if (charCode > 255) {
			    alert( "Unicode Character '" 
                        + ch 
                        + "' cannot be encoded using standard URL encoding.\n" +
				          "(URL encoding only supports 8-bit characters.)\n" +
						  "A space (+) will be substituted." );
				encoded += "+";
			} else {
				encoded += "%";
				encoded += HEX.charAt((charCode >> 4) & 0xF);
				encoded += HEX.charAt(charCode & 0xF);
			}
		}
	} // for

	
	return encoded;
};

function URLDecode(text )
{
   // Replace + with ' '
   // Replace %xx with equivalent character
   // Put [ERROR] in output if %xx is invalid.
   var HEXCHARS = "0123456789ABCDEFabcdef"; 
   var encoded = text;
   var plaintext = "";
   var i = 0;
   while (i < encoded.length) {
       var ch = encoded.charAt(i);
	   if (ch == "+") {
	       plaintext += " ";
		   i++;
	   } else if (ch == "%") {
			if (i < (encoded.length-2) 
					&& HEXCHARS.indexOf(encoded.charAt(i+1)) != -1 
					&& HEXCHARS.indexOf(encoded.charAt(i+2)) != -1 ) {
				plaintext += unescape( encoded.substr(i,3) );
				i += 3;
			} else {
				alert( 'Bad escape combination near ...' + encoded.substr(i) );
				plaintext += "%[ERROR]";
				i++;
			}
		} else {
		   plaintext += ch;
		   i++;
		}
	} // while
   return plaintext;   
};


function checkIt(string)
{
	place = navigator.userAgent.toLowerCase().indexOf(string) + 1;
	thestring = string;
	return place;
}

function createCookie(name,value,days) {
	if (days) {
		var date = new Date();
		date.setTime(date.getTime()+(days*24*60*60*1000));
		var expires = "; expires="+date.toGMTString();
	}
	else var expires = "";
	document.cookie = name+"="+value+expires+"; path=/";
}

function readCookie(name) {
	var nameEQ = name + "=";
	var ca = document.cookie.split(';');
	for(var i=0;i < ca.length;i++) {
		var c = ca[i];
		while (c.charAt(0)==' ') c = c.substring(1,c.length);
		if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
	}
	return null;
}


function checkVersionNavegador(errorIE,errorFirefox){
	
	var detect = navigator.userAgent.toLowerCase();
	var OS,browser,version,total,thestring;
	
	if (detect.indexOf('msie')!=-1) {
		browser = "Internet Explorer";
		thestring="msie";
		place = detect.indexOf('msie') + 1;
	}else if (detect.indexOf('firefox')!=-1) {
		browser = "Firefox";
		thestring="firefox";
		place = detect.indexOf('firefox') + 1;
	}else{
		browser = "";
	}
	
	if (browser != "") {
		version = detect.charAt(place + thestring.length);
		posDecimal = place + thestring.length + 1;
		if (detect.charAt(posDecimal) == '.'){	
			do{
			  version = version + '' + detect.charAt(posDecimal);		
			  posDecimal++;								
			}while (!isNaN(detect.charAt(posDecimal)));		
		}
	}
	
	if (browser == "Internet Explorer" && parseFloat( version, 10) < 6 ){
		if (readCookie("avisoVersionExplorador") == null){
			createCookie("avisoVersionExplorador","avisado",0);
			alert(errorIE);
		}
	}
	
	if (browser == "Firefox" && parseFloat( version, 10) < 1.5 ){
		if (readCookie("avisoVersionExplorador") == null){
			createCookie("avisoVersionExplorador","avisado",0);
			alert(errorFirefox);
		}
	}
}