//go:generate go get -u github.com/valyala/quicktemplate/qtc
//go:generate qtc -dir=views

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Bios-Marcel/testing_golang_stuff/data"
	"github.com/Bios-Marcel/testing_golang_stuff/views"
	"github.com/boltdb/bolt"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
)

var db *bolt.DB

func main() {
	// Open the my.db data file in your current directory.
	// It will be created if it doesn't exist.
	var err error
	db, err = bolt.Open("bolt.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Start a writable transaction.
	tx, err := db.Begin(true)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()

	// Use the transaction...
	_, err = tx.CreateBucketIfNotExists([]byte("Users"))
	if err != nil {
		panic(err)
	}
	_, err = tx.CreateBucketIfNotExists([]byte("Sessions"))
	if err != nil {
		panic(err)
	}

	// Commit the transaction and check for error.
	if err := tx.Commit(); err != nil {
		panic(err)
	}

	router := chi.NewRouter()
	// General handle, since we don't care about the method and use post when
	// comming from register or login.
	router.Handle("/", http.HandlerFunc(index))
	router.Get("/register", register)
	router.Post("/register", register)
	router.Get("/login", login)
	router.Post("/login", loginPost)
	router.Post("/logout", logout)

	if err := http.ListenAndServe(":8080", router); err != nil {
		panic(err)
	}
}

var ErrInvalidSession = errors.New("invalid session")

func getUserAndSession(request *http.Request) (*data.User, *data.Session, error) {
	cookie, err := request.Cookie("session")
	var sessionToken string
	if err != http.ErrNoCookie {
		sessionToken = strings.TrimSpace(cookie.Value)
	}

	var user *data.User
	var session *data.Session
	if sessionToken != "" {
		if err = db.View(func(tx *bolt.Tx) error {
			sessionBucket := tx.Bucket([]byte("Sessions"))
			rawSession := sessionBucket.Get([]byte(sessionToken))
			if rawSession == nil {
				return ErrInvalidSession
			}
			var tmpSession data.Session
			if errParse := json.Unmarshal(rawSession, &tmpSession); errParse != nil {
				return fmt.Errorf("cant parse session: %w", errParse)
			}

			session = &tmpSession
			return nil
		}); err != nil {
			return nil, nil, err
		}

		if err = db.View(func(tx *bolt.Tx) error {
			usersBucket := tx.Bucket([]byte("Users"))
			rawUser := usersBucket.Get([]byte(session.Email))
			if rawUser == nil {
				return ErrInvalidSession
			}

			var tmpUser data.User
			if errParse := json.Unmarshal(rawUser, &tmpUser); errParse != nil {
				return fmt.Errorf("cant parse user: %w", errParse)
			}

			user = &tmpUser
			return nil
		}); err != nil {
			return nil, nil, err
		}

		return user, session, nil
	}

	return nil, nil, nil
}

func index(responseWriter http.ResponseWriter, request *http.Request) {
	user, _, err := getUserAndSession(request)
	if err != nil {
		if err == ErrInvalidSession {
			resetSessionCookie(responseWriter)
			views.WriteIndex(responseWriter, user)
		} else {
			http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		views.WriteIndex(responseWriter, user)
	}
}

func register(responseWriter http.ResponseWriter, request *http.Request) {
	_, session, _ := getUserAndSession(request)
	if session != nil {
		http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
		return
	}

	displayName := request.PostFormValue("display_name")
	email := request.PostFormValue("email")
	password := request.PostFormValue("password")
	if email != "" {
		var sessionToken string
		err := db.Update(func(tx *bolt.Tx) error {
			usersBucket := tx.Bucket([]byte("Users"))

			rawUser, errMarshal := json.Marshal(data.User{
				Email:       email,
				Password:    password,
				DisplayName: displayName,
			})
			if errMarshal != nil {
				return errMarshal
			}

			errPut := usersBucket.Put([]byte(email), rawUser)
			if errPut != nil {
				return errPut
			}

			sessionBucket := tx.Bucket([]byte("Sessions"))
			sessionTokenUUID := uuid.Must(uuid.NewV4()).String()
			rawSession, errMarshal := json.Marshal(data.Session{
				Token: sessionTokenUUID,
				Email: email,
			})
			if errMarshal != nil {
				return errMarshal
			}
			errPut = sessionBucket.Put([]byte(sessionTokenUUID), rawSession)
			if errPut != nil {
				return errPut
			}

			sessionToken = sessionTokenUUID
			return nil
		})
		if err != nil {
			http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(responseWriter, &http.Cookie{
			Name:  "session",
			Value: sessionToken,
		})
		http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
		return
	}

	views.WriteRegister(responseWriter)
}

func login(responseWriter http.ResponseWriter, request *http.Request) {
	_, session, _ := getUserAndSession(request)
	if session != nil {
		http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
		return
	}

	views.WriteLogin(responseWriter, false)
}

var ErrUserNotFound = errors.New("user not found")

func loginPost(responseWriter http.ResponseWriter, request *http.Request) {
	if _, session, _ := getUserAndSession(request); session != nil {
		http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
		return
	}

	email := request.PostFormValue("email")
	password := request.PostFormValue("password")

	var user *data.User
	if err := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte("Users"))
		rawUser := usersBucket.Get([]byte(email))
		if rawUser == nil {
			return ErrUserNotFound
		}

		var tmpUser data.User
		if errParse := json.Unmarshal(rawUser, &tmpUser); errParse != nil {
			return fmt.Errorf("cant parse user: %w", errParse)
		}

		user = &tmpUser
		return nil
	}); err != nil {
		if err == ErrUserNotFound {
			views.WriteLogin(responseWriter, true)
		} else {
			//TODO
			http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if user.Password == password {
		var sessionToken string
		if err := db.Update(func(tx *bolt.Tx) error {
			sessionBucket := tx.Bucket([]byte("Sessions"))
			sessionTokenUUID := uuid.Must(uuid.NewV4()).String()
			rawSession, errMarshal := json.Marshal(data.Session{
				Token: sessionTokenUUID,
				Email: email,
			})
			if errMarshal != nil {
				return errMarshal
			}

			if errPut := sessionBucket.Put([]byte(sessionTokenUUID), rawSession); errPut != nil {
				return errPut
			}

			sessionToken = sessionTokenUUID
			return nil
		}); err != nil {
			//TODO
			http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		} else {
			http.SetCookie(responseWriter, &http.Cookie{
				Name:  "session",
				Value: sessionToken,
			})
			http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
		}
	} else {
		views.WriteLogin(responseWriter, true)
	}
}

func logout(responseWriter http.ResponseWriter, request *http.Request) {
	resetSessionCookie(responseWriter)
	http.Redirect(responseWriter, request, "/", http.StatusTemporaryRedirect)
}

func resetSessionCookie(responseWriter http.ResponseWriter) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	})
}
