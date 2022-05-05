<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:zul="http://www.zkoss.org/2005/zul">

	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="tabbox[@id='panels']/tabs" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
			<tab  visible="${{soffid:isUserInRole('federation-credential:query')}}" label="${{c:l('federation.token.tokens')}}" id='tabfido'>
			</tab>
		</xsl:copy>
	</xsl:template>
 

	<xsl:template match="tabbox[@id='panels']/tabpanels" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
			<tabpanel id="fido"  fulfill="tabfido.onSelect" >
 				<fido_tab  listbox="//user/listbox" model="//user/model"/>
			</tabpanel>						
		</xsl:copy>
	</xsl:template>


	<xsl:template match="/" priority="3">
		<xsl:processing-instruction name="component">name="fido_tab" macro-uri="/addon/federation/usertoken.zul"</xsl:processing-instruction>
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


</xsl:stylesheet>