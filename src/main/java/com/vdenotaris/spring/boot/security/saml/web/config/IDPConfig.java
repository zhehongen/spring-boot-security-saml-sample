package com.vdenotaris.spring.boot.security.saml.web.config;

import lombok.Builder;
import lombok.Data;

/**
 * @author hongen.zhang
 * time: 2021/4/26 16:03
 * email: hongen.zhang@things-matrix.com
 */
@Data
@Builder
public class IDPConfig {
    private String entityId;
    private String ssoUrl;
    private String x509Certificate;
}
