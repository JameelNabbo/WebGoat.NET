package com.example.vulnerable

import javax.script.ScriptEngineManager

class ExpressionEvaluator {

    // VULN: ScriptEngine.eval with user input
    fun evaluate(expression: String): Any? {
        val engine = ScriptEngineManager().getEngineByName("JavaScript")
        return engine.eval(expression)
    }

    // VULN: Reflective class loading with user input
    fun loadPlugin(className: String): Any {
        val clazz = Class.forName(className)
        return clazz.getDeclaredConstructor().newInstance()
    }

    // VULN: Reflective method invocation
    fun invokeMethod(obj: Any, methodName: String, args: Array<Any>): Any? {
        val method = obj.javaClass.getMethod(methodName)
        return method.invoke(obj, *args)
    }
}
