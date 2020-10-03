package dauth

import (
	"context"
	"fmt"

	"github.com/opentracing/opentracing-go/log"
	"github.com/thaidzai285/dzai-mp3-auth/internal/pkg/jwtman"
	models "github.com/thaidzai285/dzai-mp3-auth/internal/pkg/models/users"
	"github.com/thaidzai285/dzai-mp3-protobuf/pkg/pb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// UserService ...
type UserService struct {
	*jwtman.JWTManager
}

// NewUserService ...
func NewUserService(jwtManager *jwtman.JWTManager) *UserService {
	return &UserService{jwtManager}
}

// Login will check & accept user's email, password => token
func (s *UserService) Login(ctx context.Context, in *pb.LoginRequest) (*pb.AuthenResponse, error) {
	email := "ntduong28597@gmail.com"
	password := "duongdeptrai"

	if email != in.Email {
		return nil, status.Errorf(codes.InvalidArgument, "LOGIN FAILED")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("cannot hash password: %v", err)
	}
	
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(in.Password))
	if err != nil {
		log.Error(err)
		return nil, status.Errorf(codes.InvalidArgument, "lOGIN FAILED")
	}

	token, err := s.JWTManager.Generate(&models.User{Username: email, Role: "User"})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "INTERNAL ERROR")
	}

	return &pb.AuthenResponse{
		Bool: "success",
		Message: "success",
		Token: token,
	}, nil
}

// Register will create new user with email & password => token
func (s *UserService) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.AuthenResponse, error) {
	return &pb.AuthenResponse{}, nil
}

// GetUser will return user information
func (s *UserService) GetUser(ctx context.Context, in *emptypb.Empty) (*pb.User, error) {
	fmt.Println("halo", ctx)
	return &pb.User{}, nil
}
