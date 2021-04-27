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

import com.vdenotaris.spring.boot.security.saml.web.config.CustomMetadataGenerator;
import com.vdenotaris.spring.boot.security.saml.web.config.IDPConfig;
import com.vdenotaris.spring.boot.security.saml.web.config.SPConfig;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.Set;

@Slf4j
@Controller
@RequestMapping("/saml")
public class SSOController {

    @Value("${zhe.hostname}")
    private String hostname;

    // Logger
    private static final Logger LOG = LoggerFactory
            .getLogger(SSOController.class);

    @Autowired
    private MetadataManager metadataManager;

    private KeyManager keyManager;

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }


    //服务发现
    @RequestMapping(value = "/discovery", method = RequestMethod.GET)
    public String idpSelection(HttpServletRequest request, Model model) {

        //metadata.addMetadataProvider();不错

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null)
            LOG.debug("Current authentication instance from security context is null");
        else
            LOG.debug("Current authentication instance from security context: "
                    + this.getClass().getSimpleName());
        if (auth == null || (auth instanceof AnonymousAuthenticationToken)) {
            Set<String> idps = metadataManager.getIDPEntityNames();
            for (String idp : idps)
                LOG.info("Configured Identity Provider for SSO: " + idp);
            model.addAttribute("idps", idps);
            return "pages/discovery";
        } else {
            LOG.warn("The current user is already logged.");
            return "redirect:/landing";
        }
    }

    @GetMapping("/downloadipd")
    public void downloadipd(HttpServletResponse response) throws IOException, MessageEncodingException {

        CustomMetadataGenerator metadataGenerator = new CustomMetadataGenerator();
        IDPConfig idpConfig = IDPConfig.builder()
                .ssoUrl("https://accounts.google.com/o/saml2/idp?idpid=C037b27r1")
                .entityId("https://accounts.google.com/o/saml2?idpid=C037b27r1")
                .x509Certificate("MIIDdDCCAlygAwIBAgIGAXglU+5DMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ\n" +
                        "bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv\n" +
                        "b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjEwMzEy\n" +
                        "MDcyNTU5WhcNMjYwMzExMDcyNTU5WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN\n" +
                        "TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx\n" +
                        "CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                        "MIIBCgKCAQEA5//OEoSzYXiVOWqHR/xA5WfLF+nTPUxz2oo3ImIYzeuAswjR6ogn6ll+0CZURoEc\n" +
                        "DYro8Ky0kMz1+7cvAbhf97k7lJJ/b6qs998ukX1vREspJ6JDaz+frrl3moA88OeJzgs/hY9VOgBl\n" +
                        "UPfluXBM7WzkwGEiOvZGc/Biqd8lx/vPLk0pxLhQgPkiiOsHmtGyAD80rpwX108pYwo2NmCrB4m6\n" +
                        "NW1cM2hMD3qoqXeN6cc47xpyL+sFRyAwAzdET/gVJ7d7jZR0Lodx0mU8H4J8bBn33RD5tJahvzEn\n" +
                        "ucbiEqG2Vsi/lEzq9mWn2E+7xptiyfqbppeggOsG2YqxUp4gIwIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
                        "A4IBAQBAVS8BkSpr0UtTe9R1jlrfPIpLhpT4DeO97ZwL7ptl2XakE6YMp6l2EDxDhpYjXNAFasMQ\n" +
                        "DA7IkjeQCCccM+8CLEFgYoiPoc+prQwItOtzQbeiQv0PSxLro/vkTSC7wh39GQdL1Z++nRXquQnb\n" +
                        "1ClH+8Hr+S9SF4Oo9M+85RfPRyZ0lYqXfw5+yHHyJWrWjiWuXlBk9X6jTf8yIVNMZ9y4FuzCS7f1\n" +
                        "nsRBeztx37tefmwQvPADnWGIuWxVFbtQRhE6BOYSxBmxSA8g+L/3uAur+PCrl69RV6tSr72ZPlQR\n" +
                        "i2L6yrWBHF4dTa8CaIM96/O4sSFfFAwqfNZuV56bNgMY")
                .build();
        EntityDescriptor entityDescriptor = metadataGenerator.parseIDPMetadata(idpConfig);
        response.setContentType("application/samlmetadata+xml"); // SAML_Meta, 4.1.1 - line 1235
        response.setCharacterEncoding("UTF-8");
        response.addHeader("Content-Disposition", "attachment; filename=\"spring_saml_metadata.xml\"");
        Element element = SAMLUtil.marshallMessage(entityDescriptor);
        String metadata = XMLHelper.nodeToString(element);
        response.getWriter().print(metadata);
    }

    private EntityDescriptor getIDPEntityDescriptor() {
        CustomMetadataGenerator metadataGenerator = new CustomMetadataGenerator();
        IDPConfig idpConfig = IDPConfig.builder()
                .ssoUrl("https://accounts.google.com/o/saml2/idp?idpid=C037b27r1")
                .entityId("https://accounts.google.com/o/saml2?idpid=C037b27r1")
                .x509Certificate("MIIDdDCCAlygAwIBAgIGAXglU+5DMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ\n" +
                        "bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv\n" +
                        "b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjEwMzEy\n" +
                        "MDcyNTU5WhcNMjYwMzExMDcyNTU5WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN\n" +
                        "TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx\n" +
                        "CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                        "MIIBCgKCAQEA5//OEoSzYXiVOWqHR/xA5WfLF+nTPUxz2oo3ImIYzeuAswjR6ogn6ll+0CZURoEc\n" +
                        "DYro8Ky0kMz1+7cvAbhf97k7lJJ/b6qs998ukX1vREspJ6JDaz+frrl3moA88OeJzgs/hY9VOgBl\n" +
                        "UPfluXBM7WzkwGEiOvZGc/Biqd8lx/vPLk0pxLhQgPkiiOsHmtGyAD80rpwX108pYwo2NmCrB4m6\n" +
                        "NW1cM2hMD3qoqXeN6cc47xpyL+sFRyAwAzdET/gVJ7d7jZR0Lodx0mU8H4J8bBn33RD5tJahvzEn\n" +
                        "ucbiEqG2Vsi/lEzq9mWn2E+7xptiyfqbppeggOsG2YqxUp4gIwIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
                        "A4IBAQBAVS8BkSpr0UtTe9R1jlrfPIpLhpT4DeO97ZwL7ptl2XakE6YMp6l2EDxDhpYjXNAFasMQ\n" +
                        "DA7IkjeQCCccM+8CLEFgYoiPoc+prQwItOtzQbeiQv0PSxLro/vkTSC7wh39GQdL1Z++nRXquQnb\n" +
                        "1ClH+8Hr+S9SF4Oo9M+85RfPRyZ0lYqXfw5+yHHyJWrWjiWuXlBk9X6jTf8yIVNMZ9y4FuzCS7f1\n" +
                        "nsRBeztx37tefmwQvPADnWGIuWxVFbtQRhE6BOYSxBmxSA8g+L/3uAur+PCrl69RV6tSr72ZPlQR\n" +
                        "i2L6yrWBHF4dTa8CaIM96/O4sSFfFAwqfNZuV56bNgMY")
                .build();
        return metadataGenerator.parseIDPMetadata(idpConfig);
    }

    @GetMapping("/addIDPMetaData")
    @ResponseBody
    public void addIDPMetaData() throws MetadataProviderException {
        EntityDescriptor entityDescriptor = getIDPEntityDescriptor();
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(entityDescriptor);
        memoryProvider.initialize();

        ExtendedMetadata extendedMetadata = new ExtendedMetadata();//居然什么也自定义不了。

        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        metadataManager.addMetadataProvider(metadataProvider);//说明：加入MetadataManager
        metadataManager.refreshMetadata();

    }

    @GetMapping("/getAllMetadata")
    @ResponseBody
    public Object getAllMetadata() throws MetadataProviderException {
        List<ExtendedMetadataDelegate> availableProviders = metadataManager.getAvailableProviders();

        log.info(availableProviders.toString());
        log.info(">>>>>>>>>>>availableProviders.size: " + availableProviders.size());

        StringBuilder logMessage = new StringBuilder("availableProviders.size: " + availableProviders.size() + "\r\n");
        for (ExtendedMetadataDelegate availableProvider : availableProviders) {
            EntityDescriptor metadata = (EntityDescriptor) availableProvider.getMetadata();
            String entityID = metadata.getEntityID();
            ExtendedMetadata extendedMetadata = availableProvider.getExtendedMetadata(entityID);
            String alias = extendedMetadata.getAlias();
            boolean local = extendedMetadata.isLocal();
            logMessage.append(String.format("entityID: {%s},alias: {%s},local: {%s} \r\n", entityID, alias, local));
        }

        log.info(logMessage.toString());
        return logMessage.toString();

    }


    @GetMapping("/downloadsp")
    public void downloadsp(HttpServletResponse response) throws IOException, MarshallingException {

        SPConfig spConfig = SPConfig.builder().alias("testSaml").hostname(hostname).build();
        CustomMetadataGenerator metadataGenerator = new CustomMetadataGenerator();

        ExtendedMetadata extendedMetadata = getExtendedMetadata("testSaml");


        metadataGenerator.setKeyManager(keyManager);
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        EntityDescriptor entityDescriptor = metadataGenerator.generateSPMetadata(spConfig);
        response.setContentType("application/samlmetadata+xml"); // SAML_Meta, 4.1.1 - line 1235
        response.setCharacterEncoding("UTF-8");
        response.addHeader("Content-Disposition", "attachment; filename=\"spring_saml_metadata.xml\"");
        String metadata = SAMLUtil.getMetadataAsString(metadataManager, keyManager, entityDescriptor, extendedMetadata);
        response.getWriter().print(metadata);
    }


    private EntityDescriptor generateSPMetadata(SPConfig spConfig) {//只产生没啥用。关键是要加入内存
        ExtendedMetadata extendedMetadata = getExtendedMetadata(spConfig.getAlias());

        String baseUrl = "https://" + hostname;
        String displayFilterUrl = MetadataDisplayFilter.FILTER_URL;// /saml/metadata
        String entityId = baseUrl + displayFilterUrl + "/alias/" + spConfig.getAlias();

        MetadataGenerator metadataGenerator = new CustomMetadataGenerator();//说明: 自定义的
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        metadataGenerator.setEntityBaseURL(baseUrl);
        metadataGenerator.setEntityId(entityId);
        metadataGenerator.setKeyManager(keyManager);

        return metadataGenerator.generateMetadata();
    }

    private ExtendedMetadata getExtendedMetadata(String alias) {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(true);
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");//说明：签名算法
        extendedMetadata.setSignMetadata(true);
        extendedMetadata.setEcpEnabled(true);
        extendedMetadata.setAlias(alias);
        return extendedMetadata;
    }


    @GetMapping("/addSPMetaData")
    @ResponseBody
    public void addSPMetaData() throws MetadataProviderException {
        int random = new Random().nextInt(200);
        SPConfig spConfig = SPConfig.builder().alias("testSaml" + random).build();

        EntityDescriptor entityDescriptor = generateSPMetadata(spConfig);
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(entityDescriptor);
        memoryProvider.initialize();

        ExtendedMetadata extendedMetadata = getExtendedMetadata(spConfig.getAlias());

        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        metadataManager.addMetadataProvider(metadataProvider);//说明：加入MetadataManager
        metadataManager.refreshMetadata();

    }


}
