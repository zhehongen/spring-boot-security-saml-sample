package com.vdenotaris.spring.boot.security.saml.web.config;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

/**
 * @author hongen.zhang
 * time: 2021/4/23 20:01
 * email: hongen.zhang@things-matrix.com
 */
@Data
@Entity
public class SamlConfig {
    @Id
    @Column(columnDefinition = "varchar(64) COMMENT '主键ID'")
    private String id;
    /**
     * 目前一个公司只允许配置一个idp
     */
    @Column(columnDefinition = "varchar(64) COMMENT '公司id'", nullable = false, unique = true)
    private String companyId;

    /**
     * idp entityId。不一定唯一。因为有的idp提供商的entityId就是相同的。比如：https://idp.ssocircle.com
     */
    @Column(columnDefinition = "varchar(512) COMMENT 'idp entityId'", nullable = false)
    private String entityId;

    @Column(columnDefinition = "varchar(512) COMMENT 'idp 登录url'", nullable = false)
    private String ssoUrl;

    @Column(columnDefinition = "text(9120) COMMENT 'idp 证书公钥'", nullable = false)
    private String x509Certificate;

    @Column(columnDefinition = "bit COMMENT '是否启用saml登录, true:是 null:否'")
    private Boolean status = false;

}
