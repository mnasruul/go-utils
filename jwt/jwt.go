package jwt

import "github.com/dgrijalva/jwt-go"

func getToken(input interface{},secretKey string) (string, error)  {
	signingKey := []byte(secretKey)
 	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"claims":input})
 	tokenString, err := token.SignedString(signingKey)
	return tokenString, err
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