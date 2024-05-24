/*
   NetWitness Script Executor Main Program
   Copyright (C) 2024  Helmut Wahrmann

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/papertrail/remote_syslog2/syslog"
)

var (
	opts            *Options
	scriptCache     map[string]string
	currentHostName string
	syslogEnabled   bool
	syslogHost      string
	syslogPort      string
	syslogProtocol  string
	syslogger       *syslog.Logger
	passParmsAsJson bool
)

type SyslogMsg struct {
	Action     string
	ScriptName string `json:",omitempty"`
	Parameter  string `json:",omitempty"`
	Result     string `json:",omitempty"`
	Output     string `json:",omitempty"`
}

/*
Main execution. Start the Webserver and listen on the configured port for incoming requests
*/
func main() {
	// Getting Config and Main Options
	opts = GetOptions()

	// Setting up Logging
	var logPath string
	if opts.Config.Get("Server.LogPath") != nil {
		logPath = opts.Config.Get("Server.LogPath").(string)
	} else {
		logPath = "./logs/"
	}

	logFile, err := openLogFile(logPath + "nwscriptexecutor.log")
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Printf("Welcome to NetWitness Script Executor v.%s GPL v3", opts.Version)
	log.Printf("Copyright (C) 2024 Helmut Wahrmann.")

	// Setting up Syslog
	if opts.Config.Get("Syslog.Enabled") == true {
		log.Printf("Setting up Syslog connectivity")
		syslogEnabled = true
		syslogHost = opts.Config.Get("Syslog.Host").(string)
		syslogPort = fmt.Sprintf("%v", opts.Config.Get("Syslog.Port").(uint64))
		syslogProtocol = opts.Config.Get("Syslog.Protocol").(string)
		currentHostName, _ = os.Hostname()
		connectTimeout := time.Duration(30) * time.Second
		var err error
		syslogger, err = syslog.Dial(currentHostName, syslogProtocol, syslogHost+":"+syslogPort, nil, connectTimeout, connectTimeout, 9999)
		if err != nil {
			log.Printf("Error connecting to syslog Host %v", err)
			syslogEnabled = false
		}
	}

	if opts.Config.Get("Scripts.PassParmAsJson") == true {
		passParmsAsJson = true
	}

	// Build a cache of scripts for faster access
	scriptsFolder := opts.Config.Get("Scripts.ScriptsFolder").(string)
	buildScriptsCache(scriptsFolder)

	port := fmt.Sprintf("%v", opts.Config.Get("Server.Port").(uint64))
	var servercert string
	if opts.Config.Get("Server.ServerCertificate") != nil {
		servercert = opts.Config.Get("Server.ServerCertificate").(string)
	}

	var serverkey string
	if opts.Config.Get("Server.ServerKey") != nil {
		serverkey = opts.Config.Get("Server.ServerKey").(string)
	}

	log.Printf("Starting up the HTTP(S) Listener")
	msg, _ := json.Marshal(SyslogMsg{Action: "Starting", Output: "Server starting up"})
	sendSyslog("Info", string(msg))

	router := mux.NewRouter().SkipClean(true)
	router.HandleFunc("/script/{script}", basicAuth(action))
	router.HandleFunc("/script//{script}", basicAuth(action)) // remove when netwitness fixed the error

	// Setup channel and contect to detect service termination
	_, cancel := context.WithCancel(context.Background())
	stopHTTPServerChan := make(chan os.Signal, 1)
	signal.Notify(stopHTTPServerChan, os.Interrupt, syscall.SIGTERM)
	defer cancel() // Call cancel when program exits

	srv := &http.Server{
		Handler:      router,
		Addr:         ":" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if servercert == "" || serverkey == "" {
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatalf("Error Listenand Serve: %v", err)
				msg, _ := json.Marshal(SyslogMsg{Action: "Server", Result: "Failure", Output: err.Error()})
				sendSyslog("Error", string(msg))
			}
		} else {
			if err := srv.ListenAndServeTLS(servercert, serverkey); err != http.ErrServerClosed {
				log.Fatalf("Error Listenand Serve: %v", err)
				msg, _ := json.Marshal(SyslogMsg{Action: "Server", Result: "Failure", Output: err.Error()})
				sendSyslog("Error", string(msg))
			}
		}
	}()

	<-stopHTTPServerChan

	log.Printf("Stopping Server")
	msg, _ = json.Marshal(SyslogMsg{Action: "Stopping", Output: "Server stopping"})
	sendSyslog("Info", string(msg))

	cancel() // Cancel the context to signal shutdown
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(opts.Config.Get("Authentication.User").(string)))
			expectedPasswordHash := sha256.Sum256([]byte(opts.Config.Get("Authentication.Password").(string)))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

/*
Execute the requested script
*/
func action(w http.ResponseWriter, r *http.Request) {
	// Get the script name from the request
	vars := mux.Vars(r)
	scriptParm := vars["script"]
	script, ok := scriptCache[scriptParm]
	log.Printf("Received request to execute script %s", scriptParm)
	if !ok {
		buildScriptsCache(opts.Config.Get("Scripts.ScriptsFolder").(string))
		script, ok = scriptCache[scriptParm]
		if !ok {
			log.Printf("Error requested script %s not found in scripts folder", scriptParm)
			msg, _ := json.Marshal(SyslogMsg{Action: "Execute", ScriptName: scriptParm, Result: "Failure", Output: "Script not found"})
			sendSyslog("Error", string(msg))
			w.WriteHeader((http.StatusNotFound))
			return
		}
	}

	// NetWitness Response Actions are doing a POST with JSON Parms in the body
	log.Printf("Getting request body")
	var bodyBytes []byte
	var err error

	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			log.Fatalf("Error getting body for action: %v", err)
			msg, _ := json.Marshal(SyslogMsg{Action: "Server", Result: "Failure", Output: err.Error()})
			sendSyslog("Error", string(msg))
			return
		}
		defer r.Body.Close()
	}

	var result map[string]any
	if len(bodyBytes) > 0 {
		json.Unmarshal([]byte(bodyBytes), &result)
	} else {
		log.Fatal("Error no body for action found")
		msg, _ := json.Marshal(SyslogMsg{Action: "Server", Result: "Failure", Output: "no body supplied"})
		sendSyslog("Error", string(msg))
		return
	}

	var args string

	if passParmsAsJson {
		args = string(bodyBytes)
	} else {
		// Get the arguments from the body
		log.Printf("Building arguments out of request body")
		for k, v := range result {
			switch t := v.(type) {
			case string:
				//args += "\"" + k + "\",\"" + v.(string) + "\","
				args += k + "," + v.(string) + ","
			case []interface{}:
				for _, val := range v.([]interface{}) {
					//args += "\"" + k + "\",\"" + val.(string) + "\","
					args += k + "," + val.(string) + ","
				}
			default:
				_ = t // to get around the annoying UnusedVar thing in golang
			}
		}
		args = args[:len(args)-1]
	}
	log.Printf("Script requested: %s with arguments: %s", script, args)
	msg, _ := json.Marshal(SyslogMsg{Action: "Execute", ScriptName: script, Parameter: args})
	sendSyslog("Info", string(msg))

	go runCommand(script, args)

	// Response Action wants an immediate response
	w.WriteHeader((http.StatusOK))
}

/*
Run the command in a thread
*/
func runCommand(script string, args string) {
	// Declare buffer for script output
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Build the command
	isPython := false
	if path.Ext(script) == ".py" {
		isPython = true
	}

	var cmd *exec.Cmd
	scriptsFolder := opts.Config.Get("Scripts.ScriptsFolder").(string)
	if isPython {
		pythonPath := opts.Config.Get("Scripts.PythonPath").(string)
		cmd = exec.Command(pythonPath, scriptsFolder+script, args)
	} else {
		cmd = exec.Command(scriptsFolder+script, args)
	}

	// Execute the script
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		log.Printf("Script execution error: %s", stderr.String())
		msg, _ := json.Marshal(SyslogMsg{Action: "Execute", ScriptName: script, Result: "Failure", Output: stderr.String()})
		sendSyslog("Error", string(msg))
		return
	}

	output := strings.Split(stdout.String(), "\n")
	for _, line := range output {
		log.Printf("Script output: %s", line)
		msg, _ := json.Marshal(SyslogMsg{Action: "Execute", ScriptName: script, Parameter: args, Result: "Success", Output: line})
		sendSyslog("Info", string(msg))
	}
}

/*
Open the Log File
*/
func openLogFile(path string) (*os.File, error) {
	logFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return logFile, nil
}

/*
Build a cache of Scripts
*/
func buildScriptsCache(folder string) {
	log.Printf("Building Script Cache")
	files, err := os.ReadDir(folder)
	if err != nil {
		log.Fatal(err)
	}

	scriptCache = make(map[string]string)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		scriptCache[strings.TrimSuffix(f.Name(), path.Ext(f.Name()))] = f.Name()
	}
	log.Printf("Found %v scripts", len(scriptCache))
}

/*
Send Syslog message
*/
func sendSyslog(severity string, message string) {
	if !syslogEnabled {
		return
	}

	sev := syslog.SevInfo
	if strings.ToLower(severity) == "error" {
		sev = syslog.SevErr
	}

	packet := syslog.Packet{Severity: sev, Facility: syslog.LogLocal0, Time: time.Now().UTC(), Hostname: currentHostName, Message: message, Tag: "NwScriptexecutor"}
	syslogger.Write(packet)
}
