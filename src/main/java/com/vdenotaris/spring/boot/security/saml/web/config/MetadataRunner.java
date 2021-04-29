package com.vdenotaris.spring.boot.security.saml.web.config;


import com.vdenotaris.spring.boot.security.saml.web.controllers.SSOController;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;

@Slf4j
@Component
public class MetadataRunner implements CommandLineRunner {
    private MetadataManager metadataManager;

    @Autowired
    public void setManager(MetadataManager manager) {
        this.metadataManager = manager;
    }


    private KeyManager keyManager;

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }


    @Resource
    private SamlConfigDao samlConfigDao;

    @Resource
    private CompanyDao companyDao;


    @Resource
    private SSOController ssoController;


    @Override
    public void run(String... args) throws MetadataProviderException {
        log.info("---> MetadataRunner run...");

        List<SamlConfig> samlConfigList = samlConfigDao.findAll();

        log.info(">>>>>>>>>samlConfigList: " + samlConfigList);

        for (SamlConfig samlConfig : samlConfigList) {
//说明：sp加入内存
            Company company = companyDao.findById(samlConfig.getCompanyId()).orElse(null);
            if (company != null) {
                SPConfig spConfig = SPConfig.builder().alias(company.getCode()).build();
                EntityDescriptor spEntityDescriptor = ssoController.generateSPMetadata(spConfig);
                MetadataMemoryProvider spMemoryProvider = new MetadataMemoryProvider(spEntityDescriptor);
                spMemoryProvider.initialize();

                ExtendedMetadata spExtendedMetadata = ssoController.getExtendedMetadata(spConfig.getAlias());

                MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(spMemoryProvider, spExtendedMetadata);
                metadataManager.addMetadataProvider(spMetadataProvider);//说明：加入MetadataManager

//说明：将idp加入内存
                IDPConfig idpConfig = IDPConfig.builder().entityId(samlConfig.getEntityId())
                        .ssoUrl(samlConfig.getSsoUrl())
                        .x509Certificate(samlConfig.getX509Certificate()).build();
                EntityDescriptor idpEntityDescriptor = ssoController.getIDPEntityDescriptor(idpConfig);
                MetadataMemoryProvider idpMemoryProvider = new MetadataMemoryProvider(idpEntityDescriptor);
                idpMemoryProvider.initialize();

                ExtendedMetadata idpExtendedMetadata = new ExtendedMetadata();//居然什么也自定义不了。
                idpExtendedMetadata.setAlias(spConfig.getAlias() + "ipd");
                MetadataProvider idpMetadataProvider = new ExtendedMetadataDelegate(idpMemoryProvider, idpExtendedMetadata);
                metadataManager.addMetadataProvider(idpMetadataProvider);//说明：加入MetadataManager
            }

//说明：刷新
            metadataManager.refreshMetadata();
        }

        log.info("---> MetadataRunner finished,  count={}", metadataManager.getAvailableProviders().size());
    }
}
