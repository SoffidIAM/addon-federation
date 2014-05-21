// Paso 1

$(document).ready(function(){	
	// explicacion de los pasos
	$("#btn_pasosExplicacion").bind("click", function(e){
		$("#pasosExplicacion").slideToggle("slow");
	});
	// iconografia
	$("#iconografiaMasInfo").bind("click", function(e){
		var display = $("#iconografia ul span").css("display");
		if (display == 'none') {
			$("#iconografia ul span").fadeIn("slow");
			$("#iconografia ul").addClass("masInfo");
		} else {
			$("#iconografia ul span").fadeOut("slow", function () {
        $("#iconografia ul").removeClass();
      });
		}
	});
	// ver instrucciones de los docs
	$("#listadoPlantillas a.instrucciones").click(function () {
		$(this).parent().parent().find(".instruccionesInfo").slideToggle("slow");
	});
});