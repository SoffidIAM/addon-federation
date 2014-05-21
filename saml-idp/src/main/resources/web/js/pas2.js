// Paso 2

$(document).ready(function() {
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
});