package com.test.vulnerable;

import javax.script.*;
import javax.servlet.http.*;
import java.lang.reflect.*;

/**
 * Code Injection Test Samples
 * Tests: ScriptEngine eval, Reflection with user input
 */
public class CodeInjectionSamples {

    // 1. JavaScript engine eval with user input
    public Object evalScript(HttpServletRequest request) throws Exception {
        String code = request.getParameter("code");
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(code);
    }

    // 2. Groovy script execution
    public Object groovyEval(HttpServletRequest request) throws Exception {
        String script = request.getParameter("script");
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
        return engine.eval(script);
    }

    // 3. Reflection-based method invocation with user input
    public Object reflectInvoke(HttpServletRequest request) throws Exception {
        String className = request.getParameter("class");
        String methodName = request.getParameter("method");
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        return method.invoke(clazz.newInstance());
    }

    // 4. Dynamic class loading
    public Object loadClass(HttpServletRequest request) throws Exception {
        String className = request.getParameter("className");
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Class<?> clazz = cl.loadClass(className);
        return clazz.newInstance();
    }
}
