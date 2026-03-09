package com.test.vulnerable;

import javax.xml.parsers.*;
import org.xml.sax.*;
import javax.servlet.http.*;
import java.io.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;

/**
 * XML External Entity (XXE) Test Samples
 * Tests: DocumentBuilderFactory, SAXParser, TransformerFactory
 */
public class XxeSamples {

    // 1. DocumentBuilderFactory without security features
    public void parseXml(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(request.getInputStream());
    }

    // 2. SAXParser without security
    public void saxParse(InputStream input) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(input, new org.xml.sax.helpers.DefaultHandler());
    }

    // 3. TransformerFactory without security
    public void transformXml(InputStream input, OutputStream output) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(new StreamSource(input), new StreamResult(output));
    }

    // 4. XMLInputFactory without security
    public void staxParse(InputStream input) throws Exception {
        javax.xml.stream.XMLInputFactory factory = javax.xml.stream.XMLInputFactory.newInstance();
        javax.xml.stream.XMLStreamReader reader = factory.createXMLStreamReader(input);
        while (reader.hasNext()) {
            reader.next();
        }
    }

    // 5. SchemaFactory without security
    public void validateSchema(InputStream schemaInput) throws Exception {
        javax.xml.validation.SchemaFactory sf = javax.xml.validation.SchemaFactory.newInstance(
            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        sf.newSchema(new StreamSource(schemaInput));
    }
}
