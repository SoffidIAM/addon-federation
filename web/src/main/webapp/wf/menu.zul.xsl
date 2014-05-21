<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:zul="http://www.zkoss.org/2005/zul">
	
	<xsl:template match="/zul:zk/zul:zscript" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
		<zul:zscript>
			boolean canViewFederation = es.caib.seycon.ng.utils.Security.isUserInRole("seu:federacioIdentitats:show/*");
		</zul:zscript>
	</xsl:template>
	
	<xsl:template match="zul:tree/zul:treechildren/zul:treeitem[3]" priority="3">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
			
			<zul:treeitem open="false" if="{'${canViewFederation}'}">
				<zul:treerow >
					<zul:treecell label="{'${c:l(&quot;federation.menu&quot;)}'}" onClick="self.parent.parent.open=!self.parent.parent.open"/>
				</zul:treerow>
				<zul:treechildren>
					<zul:treeitem>
						<zul:treerow>
							<zul:apptreecell langlabel="federation.submenu"
								pagina="addon/federation/federacio.zul" />
						</zul:treerow>
					</zul:treeitem>
				</zul:treechildren>
			</zul:treeitem>
	</xsl:template>
 

	<xsl:template match="node()|@*" priority="2">
		<xsl:copy>
			<xsl:apply-templates select="node()|@*" />
		</xsl:copy>
	</xsl:template>

</xsl:stylesheet>