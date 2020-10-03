package dauth

import (
	"context"
	"fmt"
	"log"

	"github.com/thaidzai285/dzai-mp3-auth/internal/pkg/jwtman"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor ...
type AuthInterceptor struct {
	jwtManager   *jwtman.JWTManager
	allowActions map[string]bool // Not Blacklist/Whitelist actions :))
}

// NewAuthInterceptor ...
func NewAuthInterceptor(jwtManager *jwtman.JWTManager, allowActions map[string]bool) *AuthInterceptor {
	return &AuthInterceptor{jwtManager, allowActions}
}

// Unary will handle Unary rpc
func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		log.Println("--> unary interceptor: ", info.FullMethod)

		err := interceptor.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) error {
	_, ok := interceptor.allowActions[method]
	if ok {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}
	log.Println(md)

	authorization := md["authorization"]
	if len(authorization) == 0 {
		return status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}
	log.Println(authorization)

	token := authorization[0]
	claims, err := interceptor.jwtManager.Verify(token)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "token is invalid: %v", err)
	}

	fmt.Println(claims)

	return nil
}
