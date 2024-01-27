package com.example.springbootsecurityjwt.log;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.lang.reflect.Method;

@Component
public class LoggerInterceptor implements HandlerInterceptor {

    Logger loggerInterceptor = org.slf4j.LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        executionHandler(handler, StateHandler.PRE_HANDLER);
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
        executionHandler(handler,StateHandler.POST_HANDLER);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        executionHandler(handler,StateHandler.AFTER_COMPLETION);
    }

    private void executionHandler(Object handler, StateHandler stateHandler) {
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            Method method = handlerMethod.getMethod();
            if (method.isAnnotationPresent(Loggable.class)
                    && (method.getAnnotation(Loggable.class).value() == stateHandler)){
                String className = handlerMethod.getBeanType().getSimpleName();
                String methodName = method.getName();
                loggerInterceptor.info("logger_Interceptor:" + stateHandler.toString() + " execution - Class:" + className + ", Method:" + methodName);
            }

        }
    }
}


