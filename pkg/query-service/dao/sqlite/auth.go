package sqlite

import (
	"context"
	"fmt"
	"go.signoz.io/signoz/pkg/query-service/auth"
	"net/url"
	"time"

	"github.com/google/uuid"
	"go.signoz.io/signoz/pkg/query-service/constants"
	"go.signoz.io/signoz/pkg/query-service/model"
	"go.signoz.io/signoz/pkg/query-service/utils"
	"go.uber.org/zap"
)

func (mds *ModelDaoSqlite) createUserForSSORequest(ctx context.Context, email string) (*model.User, model.BaseApiError) {
	hash, err := auth.PasswordHash(utils.GeneratePassowrd())
	if err != nil {
		zap.L().Error("failed to generate password hash when registering a user via SSO redirect", zap.Error(err))
		return nil, model.InternalErrorStr("failed to generate password hash")
	}

	group, apiErr := mds.GetGroupByName(ctx, constants.ViewerGroup)
	if apiErr != nil {
		zap.L().Error("GetGroupByName failed", zap.Error(apiErr))
		return nil, apiErr
	}

	user := &model.User{
		Id:        uuid.NewString(),
		Name:      "",
		Email:     email,
		Password:  hash,
		CreatedAt: time.Now().Unix(),
		GroupId:   group.Id,
	}

	user, apiErr = mds.CreateUser(ctx, user, false)
	if apiErr != nil {
		zap.L().Error("CreateUser failed", zap.Error(apiErr))
		return nil, apiErr
	}
	return user, nil
}

// PrepareSsoRedirect prepares redirect page link after SSO response
// is successfully parsed (i.e. valid email is available)
func (mds *ModelDaoSqlite) PrepareSsoRedirect(ctx context.Context, redirectUri, email string) (redirectURL string, apierr model.BaseApiError) {

	userPayload, apierr := mds.GetUserByEmail(ctx, email)
	if !apierr.IsNil() {
		zap.L().Error("failed to get user with email received from auth provider", zap.String("error", apierr.Error()))
		return "", model.BadRequestStr("invalid user email received from the auth provider")
	}

	user := &model.User{}

	if userPayload == nil {
		newUser, apiErr := mds.createUserForSSORequest(ctx, email)
		user = newUser
		if apiErr != nil {
			zap.L().Error("failed to create user with email received from auth provider", zap.Error(apiErr))
			return "", apiErr
		}
	} else {
		user = &userPayload.User
	}

	tokenStore, err := auth.GenerateJWTForUser(user)
	if err != nil {
		zap.L().Error("failed to generate token for SSO login user", zap.Error(err))
		return "", model.InternalErrorStr("failed to generate token for the user")
	}

	return fmt.Sprintf("%s?jwt=%s&usr=%s&refreshjwt=%s",
		redirectUri,
		tokenStore.AccessJwt,
		user.Id,
		tokenStore.RefreshJwt), nil
}

func (mds *ModelDaoSqlite) SSOPrecheckLogin(ctx context.Context, email, sourceUrl string) (*model.PrecheckResponse, model.BaseApiError) {

	// assume user is valid unless proven otherwise
	resp := &model.PrecheckResponse{IsUser: true, CanSelfRegister: false}

	// check if email is a valid user
	userPayload, baseApiErr := mds.GetUserByEmail(ctx, email)
	if baseApiErr != nil {
		return resp, baseApiErr
	}

	if userPayload == nil {
		resp.IsUser = false
	}

	resp.IsUser = true

	if sourceUrl == "" {
		sourceUrl = constants.GetDefaultSiteURL()
	}

	// parse source url that generated the login request
	var err error
	escapedUrl, _ := url.QueryUnescape(sourceUrl)
	siteUrl, err := url.Parse(escapedUrl)
	if err != nil {
		zap.L().Error("failed to parse referer", zap.Error(err))
		return resp, model.InternalError(fmt.Errorf("failed to generate login request"))
	}

	// build Idp URL that will authenticat the user
	// the front-end will redirect user to this url
	resp.SsoUrl, err = orgDomain.BuildSsoUrl(siteUrl)

	if err != nil {
		zap.L().Error("failed to prepare sso request", zap.Error(err))
		return resp, model.InternalError(err)
	}

	// set SSO to true, as the url is generated correctly
	resp.SSO = true

	return resp, nil
}
