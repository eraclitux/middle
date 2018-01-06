// Copyright (c) 2015 Andrea Masi. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE.txt file.

package middle_test

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/eraclitux/middle"
)

// This example shows how to log requests for different handlers.
func ExampleLog() {
	infoLogger := log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime)

	http.HandleFunc("/bar", middle.Log(infoLogger, barHanlder))
	http.HandleFunc("/foo", middle.Log(infoLogger, fooHanlder))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func barHanlder(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello bar")
}

func fooHanlder(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello foo")
}
