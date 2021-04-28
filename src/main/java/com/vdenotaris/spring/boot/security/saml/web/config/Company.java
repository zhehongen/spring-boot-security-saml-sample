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
public class Company {
    @Id
    @Column(columnDefinition = "varchar(64) COMMENT '主键ID'")
    private String id;

    @Column(columnDefinition = "varchar(50) COMMENT '公司编码'", nullable = false)
    private String code;

    /**
     * 公司名称
     */
    @Column(columnDefinition = "varchar(255) COMMENT '公司名称'", nullable = false)
    private String name;

    /**
     * 公司网站、域名,前缀
     */
    @Column(name = "site_prefix", unique = true)
    private String sitePrefix;


}
