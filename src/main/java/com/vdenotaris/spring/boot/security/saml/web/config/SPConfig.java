package com.vdenotaris.spring.boot.security.saml.web.config;

import lombok.Builder;
import lombok.Data;

/**
 * @author hongen.zhang
 * time: 2021/4/27 11:20
 * email: hongen.zhang@things-matrix.com
 */
@Data
@Builder
public class SPConfig {
    private String hostname;
    private String alias;
}
