package aks

import (
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"k8xauth/internal/logger"

	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	statictokensource "github.com/trhyo/azidentity-static-source"
	"golang.org/x/oauth2"
)

func getCredentials(o *auth.Options, clientID, tenantID, serverID string) {
	ctx := context.Background()

	authSource, err := auth.New(o)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	if o.PrintSourceToken {
		authSource.PrettyPrintJWTToken(os.Stdout)
	}

	identityToken, err := authSource.Token()
	if err != nil {
		logger.Log.Debug(err.Error())
		os.Exit(1)
	}

	logger.Log.Debug("Getting Azure client credentials")
	DefaultAzureCredentialOptions := azidentity.DefaultAzureCredentialOptions{
		TenantID: tenantID,
	}

	// Try using default credentials source in case the workload identity federation credential fails
	defaultCredentials, err := azidentity.NewDefaultAzureCredential(&DefaultAzureCredentialOptions)
	if err != nil {
		logger.Log.Debug(fmt.Sprintf("Error getting default Azure credentials: %s", err.Error()))
	}

	WorkloadIdentityFederationCredentialOptions := statictokensource.WorkloadIdentityFederationCredentialOptions{
		DisableInstanceDiscovery: true,
		TenantID:                 tenantID,
		ClientID:                 clientID,
		FederatedToken:           *identityToken,
	}

	wfiCredentials, err := statictokensource.NewWorkloadIdentityFederationCredential(&WorkloadIdentityFederationCredentialOptions)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	chainCreds, err := azidentity.NewChainedTokenCredential([]azcore.TokenCredential{wfiCredentials, defaultCredentials}, nil)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	aztoken, err := chainCreds.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{serverID + "/.default"}, // https://azure.github.io/kubelogin/concepts/aks.html#azure-kubernetes-service-aad-server
	})
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	writer := credwriter.ExecCredentialWriter{}
	err = writer.Write(oauth2.Token{
		AccessToken: aztoken.Token,
		Expiry:      aztoken.ExpiresOn,
	}, os.Stdout)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}
