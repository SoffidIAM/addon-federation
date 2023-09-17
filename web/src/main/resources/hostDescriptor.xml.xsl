<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

	<xsl:output method="xml" omit-xml-declaration="no" indent="yes"/>

	<xsl:template match="datanode[@name='host']" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />

			<finder name="token" type="token" refreshAfterCommit="false" > 
				<ejb-finder jndi="java:/module/HostCredentialService-v2"
					method="findHostCredentials">
					<parameter value="${{instance.name}}" />
				</ejb-finder>
			</finder>
		</xsl:copy>
	</xsl:template>


	<xsl:template match="/zkib-model" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		
			<datanode name="token">
				<ejb-handler jndi="java:/module/HostCredentialService-v2">
					<delete-method method="remove">
						<parameter value="${{instance}}" />
					</delete-method>
				</ejb-handler>
			</datanode>
		</xsl:copy>
	</xsl:template>


	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>


</xsl:stylesheet>