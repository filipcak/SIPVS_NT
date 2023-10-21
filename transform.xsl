<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:ns="http://SIPVS_I_NT_ucastnici_skupina_6"
                version="1.0">

    <xsl:output method="html" encoding="UTF-8" indent="yes"/>

    <xsl:template match="/ns:ucastnici">
        <html>
            <head>
                <title>Ucastnici</title>
                <style type="text/css">
                    fieldset {
                        border: none;
                    }
                    h3 {
                        font-weight: normal;
                        ont-size: 1.5rem;
                    }
                    legend {
                        ont-size: 1.5rem;
                    }
                    body {
                    margin: 0;
                    padding: 0;
                    font-family: sans-serif;
                    }

                    h1 {
                    font-size: 2rem;
                    margin-top: 0;
                    }

                    h2 {
                    font-size: 1.5rem;
                    margin-top: 0;
                    }

                    p {
                    margin-bottom: 1rem;
                    }

                    a {
                    text-decoration: none;
                    }

                    input {
                    width: 100%;
                    padding: 0.5rem;
                    border: 1px solid #ccc;
                    border-radius: 0.5rem;
                    }

                    label {
                    font-weight: bold;
                    }

                    button {
                    background-color: #000;
                    color: #fff;
                    padding: 0.5rem 1rem;
                    border: none;
                    border-radius: 0.5rem;
                    cursor: pointer;
                    }

                    ul {
                    list-style-type: none;
                    margin: 0;
                    padding: 0;
                    }

                    li {
                    margin-bottom: 1rem;
                    }

                    form {
                    width: 500px;
                    margin: 0 auto;
                    }

                    #ucastnici {
                    display: flex;
                    flex-direction: column;
                    }

                    #pridat-ucastnika {
                    margin-top: 2rem;
                    }

                    #odoslat-posledny-ucastnik {
                    margin-top: 2rem;
                    }

                    #ucastnici-ostatne {
                    display: none;
                    }

                    .display-5 {
                    font-size: 3rem;
                    }

                    .success {
                    color: green;
                    }

                    .error {
                    color: red;
                    }

                    .popup {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.5);
                    z-index: 1000;
                    }

                    .popup-content {
                    position: absolute;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    width: 400px;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 5px;
                    }

                    .close {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    cursor: pointer;
                    }
                </style>
            </head>
            <body>
                <h1>SIPVS_NT</h1>
                <form method="post">
                    <fieldset>
                        <legend>Účastníci</legend>
                        <ul id="ucastnici">
                            <xsl:apply-templates select="ns:ucastnik"/>
                        </ul>
                    </fieldset>
                </form>
            </body>
        </html>
    </xsl:template>

    <xsl:template match="ns:ucastnik">
        <tr>
            <h3>Účastník <xsl:value-of select="position()" /></h3>
            <label>Meno:</label>
            <td><input type="text" readonly="readonly" value="{ns:meno}"/></td>
            <label>Priezvisko:</label>
            <td><input type="text" readonly="readonly" value="{ns:priezvisko}"/></td>
            <label>Dátum narodenia:</label>
            <td>
                <xsl:variable name="originalDate" select="ns:datum_narodenia" />
                <xsl:variable name="year" select="substring($originalDate, 1, 4)" />
                <xsl:variable name="month" select="substring($originalDate, 6, 2)" />
                <xsl:variable name="day" select="substring($originalDate, 9, 2)" />
                <xsl:variable name="formattedDate" select="concat($day, '.', $month, '.', $year)" />
                <input type="text" readonly="readonly" value="{$formattedDate}" />
            </td>
            <label>Vek:</label>
            <td><input type="text" readonly="readonly" value="{ns:vek}"/></td>
            <label>Email:</label>
            <td><input type="text" readonly="readonly" value="{@email}" /></td>
        </tr>
    </xsl:template>

</xsl:stylesheet>