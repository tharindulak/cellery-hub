/*
 * Copyright (c) 2019 WSO2 Inc. (http:www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http:www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/golang/glog"

	"github.com/cellery-io/cellery-hub/components/docker-auth/pkg/extension"
)

const logFile = "/extension-logs/authorization.log"

func dbConn() (*sql.DB, error) {
	dbDriver := extension.MYSQL_DRIVER
	dbUser := os.Getenv(extension.MYSQL_USER_ENV_VAR)
	dbPass := os.Getenv(extension.MYSQL_PASSWORD_ENV_VAR)
	dbName := extension.DB_NAME
	host := os.Getenv(extension.MYSQL_HOST_ENV_VAR)
	port := os.Getenv(extension.MYSQL_PORT_ENV_VAR)

	db, err := sql.Open(dbDriver, fmt.Sprint(dbUser, ":", dbPass, "@tcp(", host, ":", port, ")/"+dbName))
	if err != nil {
		log.Println("Error occurred while connecting to the database")
		return nil, err
	}
	return db, nil
}

func main() {
	glog.Info("Authentication extension reached and access will be validated")
	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer func() {
		err = file.Close()
		if err != nil {
			os.Exit(2)
		}
	}()
	if err != nil {
		log.Println("Error occurred  while closing the file :", err)
		os.Exit(extension.ErrorExitCode)
	}
	log.SetOutput(file)
	accessToken := extension.ReadStdIn()
	db, err := dbConn()
	if err != nil {
		log.Println("Error occurred while establishing the mysql connection: ", err)
		os.Exit(extension.ErrorExitCode)
	}
	isValid, err := extension.ValidateAccess(db, accessToken)
	if err != nil {
		log.Println("Error occurred while validating the user :", err)
	}
	if isValid {
		err = db.Close()
		if err != nil {
			log.Println("Error occurred while closing the db connection :", err)
		}
		log.Println("User access granted")
		os.Exit(extension.SuccessExitCode)
	} else {
		err = db.Close()
		if err != nil {
			log.Println("Error occurred while closing the db connection :", err)
		}
		log.Println("User access denied")
		os.Exit(extension.ErrorExitCode)
	}
}
