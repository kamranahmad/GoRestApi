package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"

	"github.com/gorilla/mux"
)

var tokenKey = os.Getenv("MY_JWT_TOKEN_KEY")
var mySigningKey = []byte(tokenKey)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type JwtToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

// Book Struct (Model)
type Book struct {
	ID     string  `json:"id"`
	Isbn   string  `json:"isbn"`
	Title  string  `json:"title"`
	Author *Author `json:"author"`
}

// Author Struct (Model)
type Author struct {
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
}

// Init Books var as a slice book struct
var books []Book

// Get All Books
func getBooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(books)
}

// Get Single Book
func getBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) // Get Params
	//Loop through books and find with id

	for _, item := range books {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}

	json.NewEncoder(w).Encode(&Book{})
}

// Ceate new Book
func createBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var book Book
	_ = json.NewDecoder(r.Body).Decode(&book)
	book.ID = strconv.Itoa(rand.Intn(10000000))
	books = append(books, book)
	json.NewEncoder(w).Encode(book)
}

// update Book
func updateBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for index, item := range books {
		if item.ID == params["id"] {
			books = append(books[:index], books[index+1:]...)
			var book Book
			_ = json.NewDecoder(r.Body).Decode(&book)
			book.ID = params["id"]
			books = append(books, book)
			json.NewEncoder(w).Encode(book)
		}
	}
	json.NewEncoder(w).Encode(books)
}

// delete Book
func deleteBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for index, item := range books {
		if item.ID == params["id"] {
			books = append(books[:index], books[index+1:]...)
			break
		}
	}
	json.NewEncoder(w).Encode(books)
}

func getBackUserInfo(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()

	if _, exists := params["token"]; !exists {
		fmt.Fprintf(w, "There was Error")
		return
	}

	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return mySigningKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}

}

func secureApi(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "secure API returning information")
}

func ValidateMiddleware(next func(w http.ResponseWriter, req *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			token, error := jwt.Parse(authorizationHeader, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return mySigningKey, nil
			})
			if error != nil {
				json.NewEncoder(w).Encode(Exception{Message: error.Error()})
				return
			}
			if token.Valid {
				context.Set(req, "decoded", token.Claims)
				next(w, req)
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	json.NewEncoder(w).Encode(user)
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)
	fmt.Println("received user password")
	fmt.Println(user)
	fmt.Println("----------------")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":   user.Username,
		"password":   user.Password,
		"exp":        time.Now().Add(time.Minute * 30).Unix(),
		"authorized": true,
	})
	tokenString, error := token.SignedString(mySigningKey)
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}
func main() {

	fmt.Println("my app is running")

	// Init Router
	r := mux.NewRouter()
	// Login using user pswd and get the jwt token use this token in API calls
	r.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")

	// // Mock Data -- @todo - implement DB
	books = append(books, Book{ID: "1", Isbn: "2127182", Title: "Book One", Author: &Author{Firstname: "Kamran", Lastname: "Ahmad"}})
	books = append(books, Book{ID: "2", Isbn: "4467186", Title: "Book Two", Author: &Author{Firstname: "John", Lastname: "Tyler"}})

	// Route Handlers / Endpoints
	//r.HandleFunc("/", isAuthorized(homePage)).Methods("GET")

	r.HandleFunc("/getBackUserInfo", getBackUserInfo).Methods("GET")
	r.HandleFunc("/secureApi", ValidateMiddleware(secureApi)).Methods("GET")

	r.HandleFunc("/api/books", getBooks).Methods("GET")
	r.HandleFunc("/api/books/{id}", getBook).Methods("GET")
	r.HandleFunc("/api/books", ValidateMiddleware(createBook)).Methods("POST")
	r.HandleFunc("/api/books/{id}", ValidateMiddleware(updateBook)).Methods("PUT")
	r.HandleFunc("/api/books/{id}", ValidateMiddleware(deleteBook)).Methods("DELETE")
	r.HandleFunc("/test", ValidateMiddleware(TestEndpoint)).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}
