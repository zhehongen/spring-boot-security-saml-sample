package com.vdenotaris.spring.boot.security.saml.web.config;

import org.hibernate.dialect.MySQL55Dialect;

/**
 * hibernate自动建表的编码格式
 *
 * @author hongen.zhang
 * time: 2019/11/20 16:57
 * email: hongen.zhang@things-matrix.com
 */
public class MySQL5Dialect extends MySQL55Dialect {

    @Override
    public String getTableTypeString() {
        return "ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_general_ci";
    }
}
