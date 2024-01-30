package com.example.springbootsecurityjwt.oauthfilter;

import com.example.springbootsecurityjwt.model.User;
import com.example.springbootsecurityjwt.model.plan.Consumption;
import com.example.springbootsecurityjwt.repository.ConsumptionRepository;
import com.example.springbootsecurityjwt.security.jwt.JwtUtils;
import com.example.springbootsecurityjwt.security.service.UserDetailsImpl;
import com.example.springbootsecurityjwt.security.service.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.lang.reflect.Method;

@Component
@RequiredArgsConstructor
public class OauthInterceptor implements HandlerInterceptor {

    Logger loggerInterceptor = org.slf4j.LoggerFactory.getLogger(this.getClass());

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;
    private final ConsumptionRepository consumptionRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {

        executionHandler(request, response, handler, StateHandler.PRE_HANDLER);
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, ModelAndView modelAndView) {

        executionHandler(request, response, handler, StateHandler.POST_HANDLER);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {

        executionHandler(request, response, handler, StateHandler.AFTER_COMPLETION);
    }

    private void executionHandler(HttpServletRequest request, HttpServletResponse response,
                                  Object handler, StateHandler stateHandler) {

        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            Method method = handlerMethod.getMethod();
            if (method.isAnnotationPresent(OauthFilter.class)
                    && (method.getAnnotation(OauthFilter.class).value() == stateHandler)){
                try {
                    String jwt = parseJwt(request);
                    if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                        String username = jwtUtils.getUserNameFromJwtToken(jwt);
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        UserDetailsImpl userDetailsimpl = (UserDetailsImpl) authentication.getPrincipal();
                        getConsumptionPlan(userDetailsimpl);
                    }

                } catch (Exception e) {
                    loggerInterceptor.error("Cannot set user authentication: {}", e);
                }

            }

        }
    }

    private void getConsumptionPlan(UserDetailsImpl user) {

//        try {
            Consumption consumption = consumptionRepository.findByUserId(user.getId());
            consumption.setNumberRequest(consumption.getNumberRequest() + 1);
            consumptionRepository.save(consumption);
//        } catch (Exception e) {
//            loggerInterceptor.error("error in fetch request: ", e);
//        }


    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
}


