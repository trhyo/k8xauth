package gke

import (
	"k8xauth/internal/logger"

	"context"
	"fmt"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"os"
	"time"

	"google.golang.org/api/iamcredentials/v1"

	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/api/sts/v1"
)

const (
	GRANT_TYPE           = "urn:ietf:params:oauth:grant-type:token-exchange"
	REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
	SUBJECT_TOKEN_TYPE   = "urn:ietf:params:oauth:token-type:jwt"
	SCOPE                = "https://www.googleapis.com/auth/cloud-platform"
)

func getCredentials(o *auth.Options, projectId, poolId, providerId, gcpServiceAccount string) {
	idProvider := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectId, poolId, providerId)

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
	}

	stsExchangeTokenRequest := sts.GoogleIdentityStsV1ExchangeTokenRequest{
		GrantType:          GRANT_TYPE,
		RequestedTokenType: REQUESTED_TOKEN_TYPE,
		SubjectTokenType:   SUBJECT_TOKEN_TYPE,
		Audience:           idProvider,
		Scope:              SCOPE,
		SubjectToken:       identityToken.AccessToken,
	}

	gcpStsService, err := sts.NewService(context.Background(), option.WithoutAuthentication())
	if err != nil {
		logger.Log.Debug(err.Error())
	}

	gcpStsV1Service := sts.NewV1Service(gcpStsService)

	stsToken, err := gcpStsV1Service.Token(&stsExchangeTokenRequest).Do()
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	// If no `--serviceaccount` flag is set the
	// stsToken will be used directly, allowing bindings on GCP resources
	// in the form "principal://iam.googleapis.com/projects/<proj_id_num>/locations/global/workloadIdentityPools/<wlif_pool_id>/subject/system:serviceaccount:learning:datasets-api".
	if gcpServiceAccount == "" {
		writer := credwriter.ExecCredentialWriter{}
		err = writer.Write(oauth2.Token{
			AccessToken: stsToken.AccessToken,
			Expiry:      time.Now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
		}, os.Stdout)
		if err != nil {
			logger.Log.Error(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	// If a `--serviceaccount` flag is set the
	// stsToken will be used to fetch GCP IAM credentials for the service account
	stsOauthToken := oauth2.Token{
		AccessToken: stsToken.AccessToken,
		Expiry:      time.Now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
	}

	config := &oauth2.Config{}
	iamCredentialsService, err := iamcredentials.NewService(context.Background(), option.WithTokenSource(config.TokenSource(context.Background(), &stsOauthToken)))
	if err != nil {
		logger.Log.Error(err.Error())
	}

	accessTokenRequest := iamcredentials.GenerateAccessTokenRequest{
		Lifetime: "3600s",
		Scope:    []string{SCOPE},
	}

	gcpCredentials, err := iamCredentialsService.Projects.ServiceAccounts.GenerateAccessToken("projects/-/serviceAccounts/"+gcpServiceAccount, &accessTokenRequest).Do()
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(2)
	}

	writer := credwriter.ExecCredentialWriter{}
	err = writer.Write(oauth2.Token{
		AccessToken: gcpCredentials.AccessToken,
		Expiry:      time.Now().Add(time.Second * time.Duration(stsToken.ExpiresIn)),
	}, os.Stdout)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}
