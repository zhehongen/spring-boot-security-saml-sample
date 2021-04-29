package com.vdenotaris.spring.boot.security.saml.web.config;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface SamlConfigDao extends JpaRepository<SamlConfig, String>, JpaSpecificationExecutor<SamlConfig> {

}
