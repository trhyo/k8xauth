package eks

import (
	"fmt"
	auth "k8xauth/internal/auth"
	"k8xauth/internal/credwriter"
	"k8xauth/internal/logger"

	"context"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/oauth2"
)

const (
	eksClusterIdHeader = "x-k8s-aws-id" // Header name identifying EKS cluser in STS getCallerIdentity call
	// The sts GetCallerIdentity request is valid for 15 minutes regardless of this parameters value after it has been
	// signed, but we set this unused parameter to 60 for legacy reasons (we check for a value between 0 and 60 on the
	// server side in 0.3.0 or earlier).  IT IS IGNORED.  If we can get STS to support x-amz-expires, then we should
	// set this parameter to the actual expiration, and make it configurable.
	requestPresignParam    = 60
	presignedURLExpiration = 15 * time.Minute // The actual token expiration (presigned STS urls are valid for 15 minutes after timestamp in x-amz-date).
	tokenV1Prefix          = "k8s-aws-v1."    // Prefix of a token in client.authentication.k8s.io/v1beta1 ExecCredential
)

func getCredentials(o *auth.Options, awsAssumeRoleArn, eksClusterName, stsRegion string) {

	ctx := context.Background()

	authSource, err := auth.New(o)
	if err != nil {
		logger.Log.Error(fmt.Sprintf("Failed getting token source: %s", err.Error()))
		os.Exit(1)
	}

	if o.PrintSourceToken {
		authSource.PrettyPrintJWTToken(os.Stdout)
	}

	sessionIdentifier, err := authSource.GetSessionIdentifier()
	if err != nil {
		logger.Log.Error(fmt.Sprintf("Couldn't retrieve session identifier: %s", err.Error()))
		os.Exit(1)
	}

	assumeRoleCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(stsRegion))
	if err != nil {
		logger.Log.Error("failed to load default AWS config: %s" + err.Error())
		os.Exit(1)
	}

	identityToken, err := authSource.IdentityTokenRetriever()
	if err != nil {
		logger.Log.Error("Failed to get JWT token from GCP metadata: %s" + err.Error())
		os.Exit(1)
	}

	stsAssumeClient := sts.NewFromConfig(assumeRoleCfg)
	awsCredsCache := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(
		stsAssumeClient,
		awsAssumeRoleArn,
		identityToken,
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = sessionIdentifier
		}),
	)

	awsCredentials, err := awsCredsCache.Retrieve(ctx)
	if err != nil {
		logger.Log.Error(fmt.Sprintf("Couldn't retrieve AWS credentials %s", err.Error()))
		os.Exit(1)
	}

	eksSignerCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(stsRegion),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: awsCredentials,
		}),
	)
	if err != nil {
		logger.Log.Error(fmt.Sprintf("Couldn't load AWS config using retrieved credentials %s", err.Error()))
		os.Exit(1)
	}

	stsClient := sts.NewFromConfig(eksSignerCfg)

	presignclient := sts.NewPresignClient(stsClient)
	presignedURLString, err := presignclient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(opt *sts.PresignOptions) {
		opt.Presigner = newCustomHTTPPresignerV4(opt.Presigner, map[string]string{
			eksClusterIdHeader: eksClusterName,
			"X-Amz-Expires":    "60",
		})
	})
	if err != nil {
		logger.Log.Error(fmt.Sprintf("Couldn't presign STS request %s", err.Error()))
	}

	token := tokenV1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString.URL))
	// Set token expiration to 1 minute before the presigned URL expires for some cushion
	tokenExpiration := time.Now().Local().Add(presignedURLExpiration - 1*time.Minute)

	writer := credwriter.ExecCredentialWriter{}
	err = writer.Write(oauth2.Token{
		AccessToken: token,
		Expiry:      tokenExpiration,
	}, os.Stdout)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}

type customHTTPPresignerV4 struct {
	client  sts.HTTPPresignerV4
	headers map[string]string
}

func newCustomHTTPPresignerV4(client sts.HTTPPresignerV4, headers map[string]string) sts.HTTPPresignerV4 {
	return &customHTTPPresignerV4{
		client:  client,
		headers: headers,
	}
}

func (p *customHTTPPresignerV4) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, r *http.Request,
	payloadHash string, service string, region string, signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) (url string, signedHeader http.Header, err error) {
	for key, val := range p.headers {
		r.Header.Add(key, val)
	}
	return p.client.PresignHTTP(ctx, credentials, r, payloadHash, service, region, signingTime, optFns...)
}
