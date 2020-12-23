<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:zul="http://www.zkoss.org/2005/zul">
	
	<xsl:template match="tabbox[@id='panels']/tabs" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
			<tab label="${{c:l('federacio.profile.consents')}}" id="tabconsents"/>
		</xsl:copy>
	</xsl:template>
	
	<xsl:template match="tabbox[@id='panels']/tabpanels"
		 priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
			<tabpanel fulfill="tabconsents.onSelect" >
				<div use="com.soffid.iam.addons.federation.web.ConsentsTab" id="consents">
					<datatable id="consentsTable" onRemove="ref:consents.removeConsent">
					<attribute name="columns"><![CDATA[
	- name: ${c:l('com.soffid.iam.api.ApplicationType.APPLICATION')}
	  value: name
	- name: ${c:l('com.soffid.iam.api.Audit.calendar')}
	  value: date
	  template: #{date_datetime}
	- name: ""
	  filter: false
	  sort: false
	  className: selector
	  template: <img src="${execution.contextPath }/img/remove.svg" class="imageclic" onClick="zkDatatable.sendClientAction(this, 'onRemove')"/>
					]]></attribute>
					</datatable>
				</div>
			</tabpanel>
		</xsl:copy>
			
	</xsl:template>
 

	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>

</xsl:stylesheet>