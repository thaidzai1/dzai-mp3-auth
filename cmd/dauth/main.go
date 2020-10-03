package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/thaidzai285/dzai-mp3-auth/internal/pkg/dauth"
	"github.com/thaidzai285/dzai-mp3-auth/internal/pkg/jwtman"
	"github.com/thaidzai285/dzai-mp3-protobuf/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	ctxCancel      context.CancelFunc
	ctx            context.Context
	allowedActions = map[string]bool{
		"/user.UserService/Login":    true,
		"/user.UserService/Register": true,
	}
)

const (
	secretKey     = "secret"
	tokenDuration = 15 * time.Minute
)

func main() {
	ctx, ctxCancel = context.WithCancel(context.Background())

	go func() {
		err := serverGRPC()
		if err != nil {
			log.Fatal("GRPC server error: ", err)
		}
	}()

	go func() {
		err := serverHTTP()
		if err != nil {
			log.Fatal("HTTP server error: ", err)
		}
	}()

	<-ctx.Done()
}

func serverGRPC() error {
	defer ctxCancel()

	jwtManager := jwtman.NewJWTManager(secretKey, tokenDuration)
	interceptor := dauth.NewAuthInterceptor(jwtManager, allowedActions)

	userService := dauth.NewUserService(jwtManager)
	s := grpc.NewServer(grpc.UnaryInterceptor(interceptor.Unary()))
	pb.RegisterUserServiceServer(s, userService)
	reflection.Register(s)

	log.Println("GRPC listen on 2001")
	listen, err := net.Listen("tcp", ":2001")
	if err != nil {
		return err
	}
	return s.Serve(listen)
}

func serverHTTP() error {
	defer ctxCancel()

	mux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{OrigName: true, EmitDefaults: true}))
	opts := []grpc.DialOption{grpc.WithInsecure()}
	pb.RegisterUserServiceHandlerFromEndpoint(context.Background(), mux, ":2001", opts)
	m := http.NewServeMux()
	m.Handle("/", mux)

	httpSrv := &http.Server{
		Addr:    ":2000",
		Handler: m,
	}

	log.Println("HTTP listen on 2000")
	return httpSrv.ListenAndServe()
}
