package eu.dataspace.connector.extension.kafka.broker;

import eu.dataspace.connector.dataplane.kafka.spi.AccessControlLists;
import eu.dataspace.connector.dataplane.kafka.spi.Credentials;
import eu.dataspace.connector.dataplane.kafka.spi.IdentityProvider;
import eu.dataspace.connector.extension.kafka.broker.acls.KafkaAccessControlLists;
import eu.dataspace.connector.extension.kafka.broker.openid.OpenIdConnectService;
import org.eclipse.edc.http.spi.EdcHttpClient;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provider;
import org.eclipse.edc.spi.result.ServiceResult;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.types.TypeManager;
import org.eclipse.edc.spi.types.domain.DataAddress;

import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.SASL_MECHANISM;
import static eu.dataspace.connector.dataplane.kafka.spi.KafkaBrokerDataAddressSchema.SASL_MECHANISM_GSSAPI;

public class DataPlaneKafkaDefaultServicesExtension implements ServiceExtension {

    @Inject
    private EdcHttpClient httpClient;
    @Inject
    private TypeManager typeManager;
    @Inject
    private Vault vault;

    @Provider(isDefault = true)
    public IdentityProvider identityProvider() {
        var openIdConnectService = new OpenIdConnectService(httpClient, typeManager.getMapper());
        var oidcProvider = new OpenIdConnectIdentityProvider(openIdConnectService, vault, typeManager.getMapper());
        var kerberosProvider = new KerberosIdentityProvider();

        return new IdentityProvider() {
            @Override
            public ServiceResult<Credentials> grantAccess(String dataFlowId, DataAddress dataAddress) {
                if (SASL_MECHANISM_GSSAPI.equals(dataAddress.getStringProperty(SASL_MECHANISM))) {
                    return kerberosProvider.grantAccess(dataFlowId, dataAddress);
                }
                return oidcProvider.grantAccess(dataFlowId, dataAddress);
            }

            @Override
            public ServiceResult<Void> revokeAccess(String dataFlowId) {
                // For OIDC: cleans up registered client from vault.
                // For Kerberos: no registered client exists, so this is a graceful no-op.
                return oidcProvider.revokeAccess(dataFlowId);
            }
        };
    }

    @Provider(isDefault = true)
    public AccessControlLists accessControlLists() {
        return new KafkaAccessControlLists(vault);
    }
}
