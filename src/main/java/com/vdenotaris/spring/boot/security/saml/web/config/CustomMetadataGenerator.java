package com.vdenotaris.spring.boot.security.saml.web.config;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.util.SAMLUtil;

import java.util.Collection;

/**
 * @author hongen.zhang
 * time: 2021/4/22 21:28
 * email: hongen.zhang@things-matrix.com
 */
public class CustomMetadataGenerator extends MetadataGenerator {
    public CustomMetadataGenerator() {
        super();
    }

//    @Override
//    public String getEntityAlias() {
//        // return "test" + new Random().nextInt();
//        return "testSaml";
//    }

    @SuppressWarnings("unchecked")
    public EntityDescriptor parseIDPMetadata(IDPConfig idpConfig) {
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();

        descriptor.setEntityID(idpConfig.getEntityId());

        SAMLObjectBuilder<IDPSSODescriptor> IDPSSODescriptorBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        IDPSSODescriptor idpssoDescriptor = IDPSSODescriptorBuilder.buildObject();
        idpssoDescriptor.setWantAuthnRequestsSigned(false);
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);


        // Name ID
        idpssoDescriptor.getNameIDFormats().addAll(getNameIDFormat(defaultNameID));


        Collection<String> bindingsSSO = mapAliases(getBindingsSSO());

        for (String binding : bindingsSSO) {//说明：md:SingleSignOnService
            idpssoDescriptor.getSingleSignOnServices().add(getSingleSignOnService(idpConfig.getSsoUrl(), binding));
        }

        SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) Configuration.getBuilderFactory().getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
        keyDescriptor.setUse(UsageType.SIGNING);//use


        XMLObjectBuilder<KeyInfo> keyInfoBuilder = (XMLObjectBuilder<KeyInfo>) Configuration.getBuilderFactory().getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
        KeyInfo keyInfo = keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        XMLObjectBuilder<X509Data> X509DataBuilder = (XMLObjectBuilder<X509Data>) Configuration.getBuilderFactory().getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
        X509Data x509Data = X509DataBuilder.buildObject(X509Data.DEFAULT_ELEMENT_NAME);

        XMLObjectBuilder<X509Certificate> x509CertificateBuilder = (XMLObjectBuilder<X509Certificate>) Configuration.getBuilderFactory().getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
        X509Certificate x509Certificate = x509CertificateBuilder.buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
        x509Certificate.setValue(idpConfig.getX509Certificate());

        x509Data.getX509Certificates().add(x509Certificate);

        keyInfo.getX509Datas().add(x509Data);

        keyDescriptor.setKeyInfo(keyInfo);//ds:KeyInfo

        idpssoDescriptor.getKeyDescriptors().add(keyDescriptor);

        descriptor.getRoleDescriptors().add(idpssoDescriptor);
        return descriptor;
    }

    @SuppressWarnings("unchecked")
    public SingleSignOnService getSingleSignOnService(String url, String binding) {
        SAMLObjectBuilder<SingleSignOnService> builder = (SAMLObjectBuilder<SingleSignOnService>) builderFactory.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        SingleSignOnService consumer = builder.buildObject();
        consumer.setLocation(url);
        consumer.setBinding(binding);


        return consumer;
    }

    @SuppressWarnings("unchecked")
    public EntityDescriptor generateSPMetadata(SPConfig spConfig) {
        SAMLObjectBuilder<EntityDescriptor> builder = (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor descriptor = builder.buildObject();
        String baseUrl = "https://" + spConfig.getHostname();
        String displayFilterUrl = MetadataDisplayFilter.FILTER_URL;// /saml/metadata
        String entityId = baseUrl + displayFilterUrl + "/alias/" + spConfig.getAlias();
        descriptor.setEntityID(entityId);
        String id = SAMLUtil.getNCNameString(entityId);
        descriptor.setID(id);

        SAMLObjectBuilder<SPSSODescriptor> spSSODescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        SPSSODescriptor spDescriptor = spSSODescriptorBuilder.buildObject();
        spDescriptor.setAuthnRequestsSigned(true);
        spDescriptor.setWantAssertionsSigned(true);
        spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Name ID
        spDescriptor.getNameIDFormats().addAll(getNameIDFormat(defaultNameID));


        // Populate endpoints
        int index = 0;

        // Resolve alases
        Collection<String> bindingsSSO = mapAliases(getBindingsSSO());
        Collection<String> bindingsSLO = mapAliases(getBindingsSLO());
        Collection<String> bindingsHoKSSO = mapAliases(getBindingsHoKSSO());
        //断言使用者不得与HTTP重定向，配置文件424一起使用，这同样适用于HoK配置文件
        // Assertion consumer MUST NOT be used with HTTP Redirect, Profiles 424, same applies to HoK profile
        for (String binding : bindingsSSO) {
            if (binding.equals(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
                spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(baseUrl, spConfig.getAlias(), 0 == index, index++, SAMLProcessingFilter.FILTER_URL, SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
            }//说明：md:AssertionConsumerService
            if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(baseUrl, spConfig.getAlias(), 0 == index, index++, SAMLProcessingFilter.FILTER_URL, SAMLConstants.SAML2_POST_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_PAOS_BINDING_URI)) {
                spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(baseUrl, spConfig.getAlias(), 0 == index, index++, SAMLProcessingFilter.FILTER_URL, SAMLConstants.SAML2_PAOS_BINDING_URI));
            }
        }


        for (String binding : bindingsHoKSSO) {
            if (binding.equals(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
                spDescriptor.getAssertionConsumerServices().add(getHoKAssertionConsumerService(baseUrl, spConfig.getAlias(), 0 == index, index++, SAMLWebSSOHoKProcessingFilter.WEBSSO_HOK_URL, SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                spDescriptor.getAssertionConsumerServices().add(getHoKAssertionConsumerService(baseUrl, spConfig.getAlias(), 0 == index, index++, SAMLWebSSOHoKProcessingFilter.WEBSSO_HOK_URL, SAMLConstants.SAML2_POST_BINDING_URI));
            }
        }

        for (String binding : bindingsSLO) {
            if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(baseUrl, spConfig.getAlias(), SAMLConstants.SAML2_POST_BINDING_URI));
            }//说明：md:SingleLogoutService
            if (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(baseUrl, spConfig.getAlias(), SAMLConstants.SAML2_REDIRECT_BINDING_URI));
            }
            if (binding.equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                spDescriptor.getSingleLogoutServices().add(getSingleLogoutService(baseUrl, spConfig.getAlias(), SAMLConstants.SAML2_SOAP11_BINDING_URI));
            }
        }


        // Populate key aliases
        String signingKey = getSigningKey();
        String encryptionKey = getEncryptionKey();
        String tlsKey = getTLSKey();

        // Generate key info
        if (signingKey != null) {   //md:KeyDescriptor子标签
            spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo(signingKey)));
        } else {
            log.info("Generating metadata without signing key, KeyStore doesn't contain any default private key, or the signingKey specified in ExtendedMetadata cannot be found");
        }
        if (encryptionKey != null) {
            spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.ENCRYPTION, getServerKeyInfo(encryptionKey)));
        } else {
            log.info("Generating metadata without encryption key, KeyStore doesn't contain any default private key, or the encryptionKey specified in ExtendedMetadata cannot be found");
        }
        //如果TLS密钥与签名密钥和加密密钥不同，则包含未指定用途的TLS密钥
        // Include TLS key with unspecified usage in case it differs from the singing and encryption keys
        if (tlsKey != null && !(tlsKey.equals(encryptionKey)) && !(tlsKey.equals(signingKey))) {
            spDescriptor.getKeyDescriptors().add(getKeyDescriptor(UsageType.UNSPECIFIED, getServerKeyInfo(tlsKey)));
        }

        descriptor.getRoleDescriptors().add(spDescriptor);

        return descriptor;
    }


}
