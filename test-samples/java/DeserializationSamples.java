package com.test.vulnerable;

import java.io.*;
import javax.servlet.http.*;

/**
 * Insecure Deserialization Test Samples
 * Tests: ObjectInputStream.readObject(), readUnshared()
 */
public class DeserializationSamples {

    // 1. Basic insecure deserialization from network stream
    public Object deserializeFromRequest(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    // 2. Deserialization from file
    public Object loadObject(String filePath) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object result = ois.readObject();
        ois.close();
        fis.close();
        return result;
    }

    // 3. readUnshared - equally dangerous
    public Object readUnsharedObject(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readUnshared();
    }

    // 4. Deserialization in try-with-resources
    public Object autoCloseDeserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }

    // 5. XMLDecoder - another deserialization vector
    public Object xmlDecode(InputStream input) throws Exception {
        java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(input);
        Object result = decoder.readObject();
        decoder.close();
        return result;
    }
}
