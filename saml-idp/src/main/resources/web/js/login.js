// JavaScript Document


$(document).ready(function(){
	$("#opcions div").bind("mouseenter mouseleave", function(e){
		$(this).toggleClass("over");
	});
	// eventos para los input
	$("#opcions input").click(function(e){
		e.stopPropagation();
	});
});