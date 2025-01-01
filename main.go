package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type User struct {
  gorm.Model

  Username string `gorm:"type:varchar(100);not null;uniqueIndex"`
  PassHash string `gorm:"type:varchar(100);not null"`

}

var tokenAuth *jwtauth.JWTAuth

func init() {
  tokenAuth = jwtauth.New("HS256", []byte("secret"), nil, jwt.WithAcceptableSkew(30*time.Second))
}

func register(w http.ResponseWriter, r *http.Request) {
  err := r.ParseForm()
  if err != nil {
    http.Error(w, "Unable to parse form", http.StatusBadRequest)
    return
  }

  username := r.FormValue("username")
  password := r.FormValue("password")

  db := GetDB(r)

  cr := User{Username: username, PassHash: password}

  if err := db.Create(&cr).Error; err != nil {
    fmt.Println("Error creating user")
    http.Error(w, "Error creating user", http.StatusConflict)
    return
  }

  var user User
  db.First(&user, cr.ID)
  fmt.Println(user.Username)
  fmt.Println(cr.ID)
  claims := map[string]interface{}{"user_id": cr.ID}
  jwtauth.SetExpiry(claims, time.Now().Add(time.Minute))

  _, tokenString, _ := tokenAuth.Encode(claims)

  w.Write([]byte("Token: " + tokenString))
}


func GetUserByID(w http.ResponseWriter, r *http.Request) {
  idStr := chi.URLParam(r, "id")
  id, err := strconv.Atoi(idStr)
  if err != nil {
    http.Error(w, "Invalid ID", http.StatusBadRequest)
  }
  
  db := GetDB(r)

  var user User
  db.First(&user, id)

  w.Write([]byte("Username: " + user.Username + " Password: " + user.PassHash))
}

func getMyself(w http.ResponseWriter, r * http.Request) {
  _, claims, _ := jwtauth.FromContext(r.Context())
  id := claims["user_id"]
  db := GetDB(r)
  fmt.Println(id)


  var user User
  db.First(&user, id)
  fmt.Println(user.Username)
  w.Write([]byte("You are logged in as " + user.Username))

}

func DBMiddleware(db *gorm.DB) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(
      func(w http.ResponseWriter, r *http.Request) {
        ctx := context.WithValue(r.Context(), "db", db)
        next.ServeHTTP(w, r.WithContext(ctx))
      })
  }
}

func GetDB(r *http.Request) *gorm.DB {
  db, ok := r.Context().Value("db").(*gorm.DB)
  if !ok {
    panic("Could no connect to db from Context")
  }
  return db
}

func dbInit() *gorm.DB{
  db, err := gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
  if err != nil {
    panic("Could not connect to DB!")
  }

  db.AutoMigrate(&User{})
  return db
}

func main() {
  r := chi.NewRouter()
  db := dbInit()

  r.Use(middleware.Logger)
  r.Use(DBMiddleware(db))

  r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Welcome"))
  })

  r.Route("/account", func(r chi.Router) {
    r.Post("/register", register)
    r.Get("/id/{id}", GetUserByID)
    r.Group(func(r chi.Router) {
      r.Use(jwtauth.Verifier(tokenAuth))
      r.Use(jwtauth.Authenticator(tokenAuth))
      r.Get("/me", getMyself)
    })
  })


  http.ListenAndServe(":3000", r)
}
