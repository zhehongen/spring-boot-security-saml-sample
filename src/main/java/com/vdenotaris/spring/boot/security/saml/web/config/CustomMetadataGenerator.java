package com.vdenotaris.spring.boot.security.saml.web.config;

import org.springframework.security.saml.metadata.MetadataGenerator;

/**
 * @author hongen.zhang
 * time: 2021/4/22 21:28
 * email: hongen.zhang@things-matrix.com
 */
public class CustomMetadataGenerator extends MetadataGenerator {
    public CustomMetadataGenerator() {
        super();
    }

    @Override
    public String getEntityAlias() {
        // return "test" + new Random().nextInt();
        return "testSaml";
    }
}
