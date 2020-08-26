package auth

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/lib/pq" // Including Postgres driver from here
)

type AuthType int

const (
	NoAuth AuthType = iota
	FileAuth
	PostgresAuth
)

type Auth struct {
	Username string
	Password string
}

// Stores the AuthType and AuthStore to authenticate incoming login/auth request
type AuthConfig struct {
	Type  AuthType
	Store AuthStore
}

// This interface is used for authenticating users
// Different implementation of AuthStore will authenticate using different backends.
// Like: files, DBs etc.
type AuthStore interface {
	Authenticate(username, password string) (bool, error)
}

type FileAuthStore struct {
	FilePath string
}

func (fas FileAuthStore) Authenticate(username, password string) (bool, error) {
	if auths, err := fas.LoadFile(); err != nil {
		return false, err
	} else {
		for _, a := range auths {
			if a.Username == username && a.Password == password {
				return true, nil
			}
		}
	}
	return false, errors.New("User/Password not found")
}
func (fas FileAuthStore) LoadFile() ([]Auth, error) {
	var auths []Auth

	f, err := os.Open(fas.FilePath)
	defer f.Close()
	if err != nil { // error checking is good practice
		// error *handling* is good practice.  log.Fatal sends the error
		// message to stderr and exits with a non-zero code.
		return auths, err
	}

	// os.File has no special buffering, it makes straight operating system
	// requests.  bufio.Reader does buffering and has several useful methods.
	rd := bufio.NewReader(f)

	// there are a few possible loop termination
	// conditions, so just start with an infinite loop.
	for {
		// reader.ReadLine does a buffered read up to a line terminator,
		// handles either /n or /r/n, and returns just the line without
		// the /r or /r/n.
		//line, isPrefix, err := bf.ReadLine()
		//...but (http://golang.org/pkg/bufio/#Reader.ReadLine)
		//ReadLine is a low-level line-reading primitive.
		//Most callers should use ReadBytes('\n') or ReadString('\n') instead.
		line, err := rd.ReadString('\n')

		// loop termination condition 1:  EOF.
		// this is the normal loop termination condition.
		if err == io.EOF {
			fmt.Print(line)
			break
		}

		// loop termination condition 2: some other error.
		// Errors happen, so check for them and do something with them.
		if err != nil {
			return auths, err
		}

		// loop termination condition 3: line too long to fit in buffer
		// without multiple reads.  Bufio's default buffer size is 4K.
		// Chances are if you haven't seen a line terminator after 4k
		// you're either reading the wrong file or the file is corrupt.
		//TODO

		// success.  The variable line is now a byte slice based on on
		// bufio's underlying buffer.  This is the minimal churn necessary
		// to let you look at it, but note! the data may be overwritten or
		// otherwise invalidated on the next read.  Look at it and decide
		// if you want to keep it.  If so, copy it or copy the portions
		// you want before iterating in this loop.  Also note, it is a byte
		// slice.  Often you will want to work on the data as a string,
		// and the string type conversion (shown here) allocates a copy of
		// the data.  It would be safe to send, store, reference, or otherwise
		// hold on to this string, then continue iterating in this loop.
		fmt.Print(line)
		splits := strings.Split(line, ",")
		if len(splits) >= 2 {
			var a Auth
			a.Username = splits[0]
			a.Password = splits[1]
			auths = append(auths, a)
		}
	}
	return auths, nil
}

type PostgresAuthStore struct {
	Host         string
	DatabaseName string
	Username     string
	Password     string
	TableName    string
}

func (pas PostgresAuthStore) Authenticate(username, password string) (bool, error) {
	dbinfo := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", pas.Host,
		pas.Username, pas.Password, pas.DatabaseName)
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		return false, fmt.Errorf("DB not opening: %s", err.Error())
	}
	defer db.Close()

	if rows, err := db.Query(fmt.Sprintf("SELECT username, password FROM %s WHERE username = '%s' AND password = '%s'", pas.TableName, username, password)); err == nil {
		for rows.Next() {
			var u, p string
			err = rows.Scan(&u, &p)
			if err != nil {
				fmt.Println("Error in scanning username, password:", err.Error())
				return false, err
			}
			return true, nil
		}
	} else {
		return false, err
	}
	return false, errors.New("User/Password not found")
}
