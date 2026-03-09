package com.example.vulnerable

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import org.xml.sax.InputSource
import java.io.StringReader

class XmlProcessor {

    // VULN: DocumentBuilderFactory without XXE protection
    fun parseXml(xmlData: String): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        return builder.parse(InputSource(StringReader(xmlData)))
    }

    // VULN: SAXParser without XXE protection
    fun parseSax(xmlData: String) {
        val factory = SAXParserFactory.newInstance()
        val parser = factory.newSAXParser()
        parser.parse(InputSource(StringReader(xmlData)), DefaultHandler())
    }

    // SAFE: DocumentBuilderFactory with XXE protection
    fun parseXmlSafe(xmlData: String): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        val builder = factory.newDocumentBuilder()
        return builder.parse(InputSource(StringReader(xmlData)))
    }
}

class DefaultHandler : org.xml.sax.helpers.DefaultHandler()
