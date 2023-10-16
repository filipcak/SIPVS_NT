<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ns="http://SIPVS_I_NT_ucastnici_skupina_6"
    version="1.0">

    <xsl:output method="html" encoding="UTF-8" indent="yes"/>

    <xsl:template match="/ns:ucastnici">
        <html>
            <head>
                <title>Ucastnici</title>
            </head>
            <body>
                <h1>Účastníci</h1>
                <table border="1">
                    <tr>
                        <th>Email</th>
                        <th>Meno</th>
                        <th>Priezvisko</th>
                        <th>Dátum narodenia</th>
                        <th>Vek</th>
                    </tr>
                    <xsl:apply-templates select="ns:ucastnik"/>
                </table>
            </body>
        </html>
    </xsl:template>

    <xsl:template match="ns:ucastnik">
        <tr>
            <td><xsl:value-of select="@email"/></td>
            <td><xsl:value-of select="ns:meno"/></td>
            <td><xsl:value-of select="ns:priezvisko"/></td>
            <td><xsl:value-of select="ns:datum_narodenia"/></td>
            <td><xsl:value-of select="ns:vek"/></td>
        </tr>
    </xsl:template>

</xsl:stylesheet>