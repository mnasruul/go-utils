package jwt_utils

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/mnasruul/go-utils/rest_errors"
)

func GetToken(input interface{},secretKey string) (response *string,err rest_errors.RestErr)  {
	signingKey := []byte(secretKey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"claims_value":input,
	})
	tokenString, errT := token.SignedString(signingKey)
	if errT != nil {
		return nil, rest_errors.NewInternalServerError("Error generating JWT token " ,errT)
	}
	return &tokenString, nil
}

func verifyToken(tokenString string, secretKey string) (jwt.Claims, error) {
	signingKey := []byte(secretKey)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token.Claims, err
}