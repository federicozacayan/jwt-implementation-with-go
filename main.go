package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var SECRET = []byte("super-secret-auth-key")
var api_key = "1234"

func GetJWT(w http.ResponseWriter, r *http.Request) {
	if r.Header["Access"] != nil {
		if r.Header["Access"][0] != api_key {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request1"))
			return
		} else {
			token, err := CreateJWT()
			if err != nil {
				fmt.Println(err)
				return
			}
			w.Write([]byte(token))
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request2"))
	}
}

func CreateJWT() (string, error) {
	//SigningMethod
	token := jwt.New(jwt.SigningMethodHS256)

	//payload
	claims := token.Claims.(jwt.MapClaims)

	//expiration time
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	//sing token
	tokenString, err := token.SignedString(SECRET)
	if err != nil {
		fmt.Println(err) //fmt.Println(err.Error())
		return "", err
	}
	return tokenString, nil
}

//middleware
func ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				_, ok := token.Method.(*jwt.SigningMethodHMAC)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Unauthorized"))
				}
				return SECRET, nil
			})
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			}
			if token.Valid {
				next(w, r)
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		}
	})
}

func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Super secret area!")
}

func main() {
	http.Handle("/", ValidateJWT(Home))
	http.HandleFunc("/jwt", GetJWT)
	http.ListenAndServe(":8080", nil)
}
