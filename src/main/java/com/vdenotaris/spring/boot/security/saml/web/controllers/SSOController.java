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

import com.vdenotaris.spring.boot.security.saml.web.config.*;
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
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Element;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

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


    @Resource
    private SamlConfigDao samlConfigDao;

    @Resource
    private CompanyDao companyDao;


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
    public void downloadIDP(HttpServletResponse response) throws IOException, MessageEncodingException {

        CustomMetadataGenerator metadataGenerator = new CustomMetadataGenerator();
        EntityDescriptor entityDescriptor = metadataGenerator.parseIDPMetadata(google());
        response.setContentType("application/samlmetadata+xml"); // SAML_Meta, 4.1.1 - line 1235
        response.setCharacterEncoding("UTF-8");
        response.addHeader("Content-Disposition", "attachment; filename=\"spring_saml_metadata.xml\"");
        Element element = SAMLUtil.marshallMessage(entityDescriptor);
        String metadata = XMLHelper.nodeToString(element);
        response.getWriter().print(metadata);
    }

    public EntityDescriptor getIDPEntityDescriptor(IDPConfig idpConfig) {
        CustomMetadataGenerator metadataGenerator = new CustomMetadataGenerator();
        return metadataGenerator.parseIDPMetadata(idpConfig);
    }

    private IDPConfig google() {
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
        return idpConfig;
    }

    private IDPConfig okta() {
        IDPConfig idpConfig = IDPConfig.builder()
                .build();
        idpConfig.setEntityId("http://www.okta.com/exkk7rbnoAHc2Ebwo5d6");
        idpConfig.setSsoUrl("https://dev-2964091.okta.com/app/dev-2964091_zhetest_1/exkk7rbnoAHc2Ebwo5d6/sso/saml");
        idpConfig.setX509Certificate("MIIDpjCCAo6gAwIBAgIGAXYDJy/vMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYDVQQGEwJVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU MBIGA1UECwwLU1NPUHJvdmlkZXIxFDASBgNVBAMMC2Rldi0yOTY0MDkxMRwwGgYJKoZIhvcNAQkB Fg1pbmZvQG9rdGEuY29tMB4XDTIwMTEyNjA2MDMyOFoXDTMwMTEyNjA2MDQyOFowgZMxCzAJBgNV BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYD VQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEUMBIGA1UEAwwLZGV2LTI5NjQwOTExHDAa BgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB AQCBRKh4Gxd9MaOgWnA9HGp02O5mVP4XSDuYct4LV5A8U6NheU1wheBD8sOCi7LbnNkcuDZuqXqC 3YB3rGQRa0X+31TASd7QIrtNkuofqk3kMii4zhVH/T9qLKFU23MDFBJBzlZoVqNsql082TeByf3R h6RqMf5B7xW5E9nj5d/qN6RPF4SIhgwQ+6Pipu1h1DK10zEf1AweuPhPXxPSkqYkS0Igm/K0jEDW Te3fIU7WAjq9BQ1iHc5rG8GPEVlCqJtwYT1hoFl/ujpeOFMMGh6pNL7p0PtmIRxftYWgS6MEHahO 1unCZ/ej/Ci6d6dqoOCPRZm9SWEhEC2sn9x4W4GpAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHeo ckKNh5JE1dzZw9lO4RjkXnoF6UQPurvoHpyTPAsFQ6ek4Flj6YvkgMxMZdyOmx/Rd0LJvhv+anNO wyIvbAGK1N20wLmzGr1oXHXHi5hxqKt2Kqj7a3z94X5thh5WYVvaxP3U2e/0M3Y6qz2u5Cq0ReVG V+/uwyIt4huwe+NqL3jor0Vu4n6RXl3FnN9ZwwvzAtKN+FUhnlz3bEFQ1SVr2HH/SrXRrxSKBRK9 fbi8fnnHEiF63UOtb8b3THQ6Ib2BJXXE8AOR+EKFFEopxMMY2a4cfcT/+L4JArODx9/N571GWah+ owVUdUqw3djrhrFm3seamlEXN0PM/i0j9Nk=");
        return idpConfig;
    }

    private IDPConfig ssocircle() {
        IDPConfig idpConfig = IDPConfig.builder()
                .build();
        idpConfig.setEntityId("https://idp.ssocircle.com");
        idpConfig.setSsoUrl("https://idp.ssocircle.com:443/sso/SSOPOST/metaAlias/publicidp");
        idpConfig.setX509Certificate("MIIEYzCCAkugAwIBAgIDIAZmMA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNVBAYTAkRF MRIwEAYDVQQKDAlTU09DaXJjbGUxCzAJBgNVBAMMAkNBMB4XDTE2MDgwMzE1MDMy M1oXDTI2MDMwNDE1MDMyM1owPTELMAkGA1UEBhMCREUxEjAQBgNVBAoTCVNTT0Np cmNsZTEaMBgGA1UEAxMRaWRwLnNzb2NpcmNsZS5jb20wggEiMA0GCSqGSIb3DQEB AQUAA4IBDwAwggEKAoIBAQCAwWJyOYhYmWZF2TJvm1VyZccs3ZJ0TsNcoazr2pTW cY8WTRbIV9d06zYjngvWibyiylewGXcYONB106ZNUdNgrmFd5194Wsyx6bPvnjZE ERny9LOfuwQaqDYeKhI6c+veXApnOfsY26u9Lqb9sga9JnCkUGRaoVrAVM3yfghv /Cg/QEg+I6SVES75tKdcLDTt/FwmAYDEBV8l52bcMDNF+JWtAuetI9/dWCBe9VTC asAr2Fxw1ZYTAiqGI9sW4kWS2ApedbqsgH3qqMlPA7tg9iKy8Yw/deEn0qQIx8Gl VnQFpDgzG9k+jwBoebAYfGvMcO/BDXD2pbWTN+DvbURlAgMBAAGjezB5MAkGA1Ud EwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmlj YXRlMB0GA1UdDgQWBBQhAmCewE7aonAvyJfjImCRZDtccTAfBgNVHSMEGDAWgBTA 1nEA+0za6ppLItkOX5yEp8cQaTANBgkqhkiG9w0BAQsFAAOCAgEAAhC5/WsF9ztJ Hgo+x9KV9bqVS0MmsgpG26yOAqFYwOSPmUuYmJmHgmKGjKrj1fdCINtzcBHFFBC1 maGJ33lMk2bM2THx22/O93f4RFnFab7t23jRFcF0amQUOsDvltfJw7XCal8JdgPU g6TNC4Fy9XYv0OAHc3oDp3vl1Yj8/1qBg6Rc39kehmD5v8SKYmpE7yFKxDF1ol9D KDG/LvClSvnuVP0b4BWdBAA9aJSFtdNGgEvpEUqGkJ1osLVqCMvSYsUtHmapaX3h iM9RbX38jsSgsl44Rar5Ioc7KXOOZFGfEKyyUqucYpjWCOXJELAVAzp7XTvA2q55 u31hO0w8Yx4uEQKlmxDuZmxpMz4EWARyjHSAuDKEW1RJvUr6+5uA9qeOKxLiKN1j o6eWAcl6Wr9MreXR9kFpS6kHllfdVSrJES4ST0uh1Jp4EYgmiyMmFCbUpKXifpsN WCLDenE3hllF0+q3wIdu+4P82RIM71n7qVgnDnK29wnLhHDat9rkC62CIbonpkVY mnReX0jze+7twRanJOMCJ+lFg16BDvBcG8u0n/wIDkHHitBI7bU1k6c6DydLQ+69 h8SCo6sO9YuD+/3xAGKad4ImZ6vTwlB4zDCpu6YgQWocWRXE+VkOb+RBfvP755PU aLfL63AFVlpOnEpIio5++UjNJRuPuAA=");
        return idpConfig;
    }

    @PostMapping("/addIDPMetaData")
    @ResponseBody
    public IDPConfig addIDPMetaData(@RequestBody IDPConfig idpConfig) throws MetadataProviderException {
        EntityDescriptor entityDescriptor = getIDPEntityDescriptor(idpConfig);
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(entityDescriptor);
        memoryProvider.initialize();

        ExtendedMetadata extendedMetadata = new ExtendedMetadata();//居然什么也自定义不了。

        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        metadataManager.addMetadataProvider(metadataProvider);//说明：加入MetadataManager
        metadataManager.refreshMetadata();
        return idpConfig;
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
    public void downloadSP(HttpServletResponse response) throws IOException, MarshallingException {

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


    public EntityDescriptor generateSPMetadata(SPConfig spConfig) {//只产生没啥用。关键是要加入内存
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

    public ExtendedMetadata getExtendedMetadata(String alias) {
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
    public String addSPMetaData() throws MetadataProviderException {
        int random = new Random().nextInt(200);
        SPConfig spConfig = SPConfig.builder().alias("testSaml" + random).build();

        EntityDescriptor entityDescriptor = generateSPMetadata(spConfig);
        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(entityDescriptor);
        memoryProvider.initialize();

        ExtendedMetadata extendedMetadata = getExtendedMetadata(spConfig.getAlias());

        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        metadataManager.addMetadataProvider(metadataProvider);//说明：加入MetadataManager
        metadataManager.refreshMetadata();
        return String.valueOf(random);
    }


    @RequestMapping("/addCompanyAndSaml")
    @ResponseBody
    @Transactional(rollbackFor = Exception.class)
    public String addCompanyAndSaml(@RequestParam(required = false) String idp) throws MetadataProviderException {
        String random = String.valueOf(new Random().nextInt(200));
//创建公司
        Company company = Company.builder()
                .id(random)
                .code("code" + random)
                .name("company " + random)
                .sitePrefix("site" + random)
                .build();
        companyDao.save(company);
//说明：创建saml配置
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setId(UUID.randomUUID().toString());
        samlConfig.setCompanyId(company.getId());
        samlConfig.setStatus(true);
        IDPConfig idpConfig;
        if ("okta".equalsIgnoreCase(idp)) {
            idpConfig = okta();
        } else if ("circle".equalsIgnoreCase(idp)) {
            idpConfig = ssocircle();
        } else {
            idpConfig = google();
        }
        samlConfig.setEntityId(idpConfig.getEntityId());
        samlConfig.setSsoUrl(idpConfig.getSsoUrl());
        samlConfig.setX509Certificate(idpConfig.getX509Certificate());
        samlConfigDao.save(samlConfig);

//说明：sp加入内存
        SPConfig spConfig = SPConfig.builder().alias("code" + random).build();
        EntityDescriptor spEntityDescriptor = generateSPMetadata(spConfig);
        MetadataMemoryProvider spMemoryProvider = new MetadataMemoryProvider(spEntityDescriptor);
        spMemoryProvider.initialize();

        ExtendedMetadata spExtendedMetadata = getExtendedMetadata(spConfig.getAlias());

        MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(spMemoryProvider, spExtendedMetadata);
        metadataManager.addMetadataProvider(spMetadataProvider);//说明：加入MetadataManager

//说明：将idp加入内存
        EntityDescriptor idpEntityDescriptor = getIDPEntityDescriptor(idpConfig);
        MetadataMemoryProvider idpMemoryProvider = new MetadataMemoryProvider(idpEntityDescriptor);
        idpMemoryProvider.initialize();

        ExtendedMetadata idpExtendedMetadata = new ExtendedMetadata();//居然什么也自定义不了。
        idpExtendedMetadata.setAlias(spConfig.getAlias() + "ipd");
        MetadataProvider idpMetadataProvider = new ExtendedMetadataDelegate(idpMemoryProvider, idpExtendedMetadata);
        metadataManager.addMetadataProvider(idpMetadataProvider);//说明：加入MetadataManager

//说明：刷新
        metadataManager.refreshMetadata();


        return random;
    }


}
