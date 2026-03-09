package com.example.vulnerable

import java.io.ObjectInputStream
import java.io.ByteArrayInputStream
import com.fasterxml.jackson.databind.ObjectMapper

class DataProcessor {

    // VULN: Java ObjectInputStream deserialization
    fun deserializeObject(data: ByteArray): Any? {
        val bis = ByteArrayInputStream(data)
        val ois = ObjectInputStream(bis)
        return ois.readObject()
    }

    // VULN: Jackson enableDefaultTyping
    fun configureJackson(): ObjectMapper {
        val mapper = ObjectMapper()
        mapper.enableDefaultTyping()
        return mapper
    }

    // VULN: Gson with dynamic type
    fun parseJson(json: String, typeName: String): Any {
        val gson = com.google.gson.Gson()
        val type = Class.forName(typeName)
        return gson.fromJson(json, type)
    }

    // VULN: Kotlin serialization with polymorphic
    fun configureSerializer() {
        val module = kotlinx.serialization.modules.SerializersModule {
            polymorphic(Base::class) {
                subclass(Derived::class)
            }
        }
    }
}

open class Base
class Derived : Base()
