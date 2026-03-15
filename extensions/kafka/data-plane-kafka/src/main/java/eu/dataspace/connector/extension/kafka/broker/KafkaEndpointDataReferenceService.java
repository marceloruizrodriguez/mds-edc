package eu.dataspace.connector.extension.kafka.broker;

import eu.dataspace.connector.dataplane.kafka.spi.AccessControlLists;
import eu.dataspace.connector.dataplane.kafka.spi.Credentials;
import eu.dataspace.connector.dataplane.kafka.spi.IdentityProvider;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.eclipse.edc.connector.dataplane.spi.DataFlow;
import org.eclipse.edc.connector.dataplane.spi.edr.EndpointDataReferenceService;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Properties;

import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.BOOTSTRAP_SERVERS;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.KAFKA_CONSUMER_PROPERTIES;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.KERBEROS_KEYTAB_PATH;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.KERBEROS_PRINCIPAL;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.KERBEROS_SERVICE_NAME;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.OIDC_CLIENT_ID;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.OIDC_CLIENT_SECRET;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.OIDC_TOKEN_ENDPOINT;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.SASL_MECHANISM;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.SASL_MECHANISM_GSSAPI;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.SECURITY_PROTOCOL;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.TOPIC;
import static org.eclipse.edc.spi.types.domain.edr.EndpointDataReference.EDR_SIMPLE_TYPE;

/**
 * Manages EDR creation and revocation for Kafka-PULL transfers
 */
class KafkaEndpointDataReferenceService implements EndpointDataReferenceService {
    private final IdentityProvider identityProvider;
    private final AccessControlLists accessControlLists;

    public KafkaEndpointDataReferenceService(IdentityProvider identityProvider, AccessControlLists accessControlLists) {
        this.identityProvider = identityProvider;
        this.accessControlLists = accessControlLists;
    }

    @Override
    public Result<DataAddress> createEndpointDataReference(DataFlow dataFlow) {
        var dataAddress = dataFlow.getSource();

        var edr = identityProvider.grantAccess(dataFlow.getId(), dataAddress)
                .<DataAddress, ServiceResult<DataAddress>>compose(credentials -> accessControlLists.allowAccessTo(credentials.subject(), dataFlow.getId(), dataAddress)
                        .map(response -> {
                            var kafkaConsumerProperties = kafkaConsumerProperties(credentials, dataAddress, response.groupId());
                            return createEdr(kafkaConsumerProperties, credentials, dataAddress);
                        }));

        return edr
                .flatMap(result -> {
                    if (result.succeeded()) {
                        return Result.success(result.getContent());
                    } else {
                        return Result.failure(result.getFailureDetail());
                    }
                });
    }

    @Override
    public ServiceResult<Void> revokeEndpointDataReference(String transferProcessId, String reason) {
        return accessControlLists.denyAccessTo(transferProcessId)
                .compose(v -> identityProvider.revokeAccess(transferProcessId));
    }

    private DataAddress createEdr(Properties kafkaConsumerProperties, Credentials credentials, DataAddress dataAddress) {
        var builder = DataAddress.Builder.newInstance()
                .type(EDR_SIMPLE_TYPE)
                .property(KAFKA_CONSUMER_PROPERTIES, serializeToString(kafkaConsumerProperties))
                .property(TOPIC, dataAddress.getStringProperty(TOPIC));

        if (credentials.clientId() != null) {
            builder.property(OIDC_CLIENT_ID, credentials.clientId());
        }
        if (credentials.clientSecret() != null) {
            builder.property(OIDC_CLIENT_SECRET, credentials.clientSecret());
        }
        if (credentials.tokenEndpoint() != null) {
            builder.property(OIDC_TOKEN_ENDPOINT, credentials.tokenEndpoint());
        }

        return builder.build();
    }

    private @NotNull Properties kafkaConsumerProperties(Credentials credentials, DataAddress dataAddress, String groupId) {
        var props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, dataAddress.getStringProperty(BOOTSTRAP_SERVERS));
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());

        props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, dataAddress.getStringProperty(SECURITY_PROTOCOL));
        props.put(SaslConfigs.SASL_MECHANISM, dataAddress.getStringProperty(SASL_MECHANISM));

        if (SASL_MECHANISM_GSSAPI.equals(dataAddress.getStringProperty(SASL_MECHANISM))) {
            configureKerberos(props, dataAddress);
        } else {
            configureOAuthBearer(props, credentials);
        }

        return props;
    }

    private void configureOAuthBearer(Properties props, Credentials credentials) {
        props.put(SaslConfigs.SASL_JAAS_CONFIG, "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required clientId=\"%s\" clientSecret=\"%s\";"
                .formatted(credentials.clientId(), credentials.clientSecret()));
        props.put(SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL, credentials.tokenEndpoint());
        props.put(SaslConfigs.SASL_LOGIN_CALLBACK_HANDLER_CLASS, OAuthBearerLoginCallbackHandler.class.getName());
    }

    private void configureKerberos(Properties props, DataAddress dataAddress) {
        var principal = dataAddress.getStringProperty(KERBEROS_PRINCIPAL);
        var serviceName = dataAddress.getStringProperty(KERBEROS_SERVICE_NAME);
        var keytabPath = dataAddress.getStringProperty(KERBEROS_KEYTAB_PATH);

        props.put(SaslConfigs.SASL_KERBEROS_SERVICE_NAME, serviceName != null ? serviceName : "kafka");

        String jaasConfig = buildKerberosJaasConfig(principal, keytabPath);
        props.put(SaslConfigs.SASL_JAAS_CONFIG, jaasConfig);
    }

    private @NotNull String buildKerberosJaasConfig(String principal, @Nullable String keytabPath) {
        if (keytabPath != null && !keytabPath.isBlank()) {
            return "com.sun.security.auth.module.Krb5LoginModule required useKeyTab=true storeKey=true keyTab=\"%s\" principal=\"%s\";"
                    .formatted(keytabPath, principal);
        }
        return "com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true principal=\"%s\";"
                .formatted(principal);
    }

    private String serializeToString(Properties properties) {
        try (var writer = new StringWriter()) {
            properties.store(writer, "Serialized kafka admin properties");
            return writer.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
