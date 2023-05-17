package main

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type UserClaims struct {
	User User `json:"user"`
	jwt.StandardClaims
}

type LoginDTO struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

func main() {
	// hashed string "root"
	hashedPassword := []byte("$2a$12$CC8DbDz4Jspvm5ueJjheneu8zIiLmACCLBJ0pvj0ODibN7DH/rECW")
	mySigningKey := []byte("key")

	httpServer := echo.New()

	config := echojwt.Config{
		SigningKey: mySigningKey,
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			log.Println(auth)
			token, err := jwt.ParseWithClaims(auth, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				return mySigningKey, nil
			})

			if err != nil {
				return nil, err
			}

			if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
				log.Println("parse ", claims.User)
				return &User{
					Username: claims.User.Username,
					Role:     claims.User.Role,
				}, nil
			}

			return nil, fmt.Errorf("parsing token due eror")
		},
	}

	httpServer.Use(echojwt.WithConfig(config))

	httpServer.GET("/", func(c echo.Context) error {
		log.Println("tut", c.Get("user"))
		user := c.Get("user").(*User)

		return c.JSON(http.StatusOK, user)
	})

	httpServer.POST("/login", func(c echo.Context) error {
		dto := new(LoginDTO)
		if err := c.Bind(dto); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(dto.Password)); err != nil {
			return c.JSON(http.StatusOK, "not compare")
		} else {
			user := User{"root", "root"}
			claims := UserClaims{
				user,
				jwt.StandardClaims{
					ExpiresAt: int64(3000 * time.Second),
					Issuer:    "test",
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			signedToken, err := token.SignedString(mySigningKey)
			if err != nil {
				log.Fatalf("generate token due error: %v", err)
			}

			return c.JSON(http.StatusOK, &LoginResponse{
				Token: signedToken,
				Role:  "admin",
			})
		}
	})

	if err := httpServer.Start("localhost:3080"); err != nil {
		log.Fatalf("start server due error: %v", err)
	}

}
