/*
 * Copyright 2020 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.vdenotaris.spring.boot.security.saml.web.controllers;

import com.vdenotaris.spring.boot.security.saml.web.config.Company;
import com.vdenotaris.spring.boot.security.saml.web.config.CompanyDao;
import com.vdenotaris.spring.boot.security.saml.web.config.SamlConfig;
import com.vdenotaris.spring.boot.security.saml.web.config.SamlConfigDao;
import com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@Controller
@Slf4j
public class LandingController {

    // Logger
    private static final Logger LOG = LoggerFactory
            .getLogger(LandingController.class);

    @Resource
    private SamlConfigDao samlConfigDao;

    @Resource
    private CompanyDao companyDao;

    @Value("${zhe.hostname}")
    private String hostname;

    @Value("${zhe.scheme}")
    private String scheme;

    @RequestMapping("/landing")
    public String landing(@CurrentUser User user, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null)
            LOG.debug("Current authentication instance from security context is null");
        else
            LOG.debug("Current authentication instance from security context: "
                    + this.getClass().getSimpleName());
        model.addAttribute("username", user.getUsername());
        return "pages/landing";
    }


    @GetMapping("/samllogin")
    public String samlLogin(Model model, HttpServletRequest request) {
        model.addAttribute("loginLink", "http://localhost:9120/login");
        return "loginSaml";
    }

    @PostMapping("/samllogin")
    public String samlLoginBegin(HttpServletRequest request) {
        String domain = request.getParameter("domain");
//说明：根据域名找到公司，根据公司找到samlConfig
        Company company = companyDao.findBySitePrefix(domain);
        SamlConfig samlConfig = samlConfigDao.findByCompanyIdAndStatusIsTrue(company.getId());
        String url = scheme + "://" + hostname + "/saml/login/alias/" + company.getCode() + "?idp=" + samlConfig.getEntityId();
        log.info(">>>>>>>>>>>>>>login Url: " + url);
        return "redirect:" + url;
    }

}
