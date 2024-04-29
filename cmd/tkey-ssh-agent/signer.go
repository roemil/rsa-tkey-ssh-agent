// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
	"github.com/tillitis/tkeyutil"
	"golang.org/x/crypto/ssh"
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
// Makefile copies the built app here ./app.bin
//
//go:embed signer.bin-v0.0.7
var appBinary []byte

const appName string = "tkey-device-signer 0.0.7"

var notify = func(msg string) {
	tkeyutil.Notify(progname, msg)
}

const (
	idleDisconnect = 3 * time.Second
	// 4 chars each.
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "tk1 "
	wantAppName1 = "sign"
)

type Signer struct {
	tk              *tkeyclient.TillitisKey
	tkSigner        *tkeysign.Signer
	devPath         string
	speed           int
	enterUSS        bool
	fileUSS         string
	pinentry        string
	mu              sync.Mutex
	connected       bool
	disconnectTimer *time.Timer
}

type AlgorithmSigner struct {
	signer Signer
}

type MultiAlgorithmSigner struct {
	signer AlgorithmSigner
}

func NewAlgorithmSinger(devPathArg string, speedArg int, enterUSS bool, fileUSS string, pinentry string, exitFunc func(int)) *AlgorithmSigner {
	var signer AlgorithmSigner
	signer.signer = *NewSigner(devPathArg, speedArg, enterUSS, fileUSS, pinentry, exitFunc)
	return &signer
}

func NewMultiAlgorithmSinger(devPathArg string, speedArg int, enterUSS bool, fileUSS string, pinentry string, exitFunc func(int)) *MultiAlgorithmSigner {
	var signer MultiAlgorithmSigner
	signer.signer = *NewAlgorithmSinger(devPathArg, speedArg, enterUSS, fileUSS, pinentry, exitFunc)
	return &signer
}

func NewSigner(devPathArg string, speedArg int, enterUSS bool, fileUSS string, pinentry string, exitFunc func(int)) *Signer {
	var signer Signer

	tkeyclient.SilenceLogging()

	tk := tkeyclient.New()

	tkSigner := tkeysign.New(tk)
	signer = Signer{
		tk:       tk,
		tkSigner: &tkSigner,
		devPath:  devPathArg,
		speed:    speedArg,
		enterUSS: enterUSS,
		fileUSS:  fileUSS,
		pinentry: pinentry,
	}

	// Do nothing on HUP, in case old udev rule is still in effect
	handleSignals(func() {}, syscall.SIGHUP)

	// Start handling signals here to catch abort during USS entering
	handleSignals(func() {
		signer.closeNow()
		exitFunc(1)
	}, os.Interrupt, syscall.SIGTERM)

	return &signer
}

func (s *MultiAlgorithmSigner) connect() bool {
	return s.signer.connect()
}

func (s *AlgorithmSigner) connect() bool {
	return s.signer.connect()
}

func (s *Signer) connect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disconnectTimer != nil {
		s.disconnectTimer.Stop()
		s.disconnectTimer = nil
	}

	if s.connected {
		return true
	}

	devPath := s.devPath
	if devPath == "" {
		var err error
		devPath, err = tkeyclient.DetectSerialPort(false)
		if err != nil {
			switch {
			case errors.Is(err, tkeyclient.ErrNoDevice):
				notify("Could not find any TKey plugged in.")
			case errors.Is(err, tkeyclient.ErrManyDevices):
				notify("Cannot work with more than 1 TKey plugged in.")
			default:
				notify(fmt.Sprintf("TKey detection failed: %s\n", err))
			}
			le.Printf("Failed to detect port: %v\n", err)
			return false
		}
		le.Printf("Auto-detected serial port %s\n", devPath)
	}

	le.Printf("Connecting to TKey on serial port %s\n", devPath)
	if err := s.tk.Connect(devPath, tkeyclient.WithSpeed(s.speed)); err != nil {
		notify(fmt.Sprintf("Could not connect to a TKey on port %v.", devPath))
		le.Printf("Failed to connect: %v", err)
		return false
	}

	if s.isFirmwareMode() {
		le.Printf("TKey is in firmware mode.\n")
		if err := s.loadApp(); err != nil {
			le.Printf("Failed to load app: %v\n", err)
			s.closeNow()
			return false
		}
	}

	if !s.isWantedApp() {
		// Notifying because we're kinda stuck if we end up here
		notify("Please remove and plug in your TKey again\n— it might be running the wrong app.")
		le.Printf("No TKey on the serial port, or it's running wrong app (and is not in firmware mode)")
		s.closeNow()
		return false
	}

	// We nowadays disconnect from the TKey when idling, so the
	// signer-app that's running may have been loaded by somebody
	// else. Therefore we can never be sure it has USS according to
	// the flags that tkey-ssh-agent was started with. So we no longer
	// say anything about that.

	s.connected = true
	return true
}

func (s *Signer) isFirmwareMode() bool {
	nameVer, err := s.tk.GetNameVersion()
	if err != nil {
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantFWName0 &&
		nameVer.Name1 == wantFWName1
}

func (s *Signer) isWantedApp() bool {
	nameVer, err := s.tkSigner.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return false
	}
	fmt.Fprintf(os.Stdout, "GetAppNameVersion: %s\n", nameVer.Name0)
	fmt.Fprintf(os.Stdout, "GetAppNameVersion: %s\n", nameVer.Name1)
	// not caring about nameVer.Version
	return nameVer.Name0 == wantAppName0 &&
		nameVer.Name1 == wantAppName1
}

func (s *Signer) loadApp() error {
	var secret []byte
	if s.enterUSS {
		udi, err := s.tk.GetUDI()
		if err != nil {
			return fmt.Errorf("Failed to get UDI: %w", err)
		}

		secret, err = getSecret(udi.String(), s.pinentry)
		if err != nil {
			notify(fmt.Sprintf("Could not show USS prompt: %s", errors.Unwrap(err)))
			return fmt.Errorf("Failed to get USS: %w", err)
		}
	} else if s.fileUSS != "" {
		var err error
		secret, err = tkeyutil.ReadUSS(s.fileUSS)
		if err != nil {
			notify(fmt.Sprintf("Could not read USS file: %s", err))
			return fmt.Errorf("Failed to read uss-file %s: %w", s.fileUSS, err)
		}
	}

	le.Printf("Loading signer app...\n")
	if err := s.tk.LoadApp(appBinary, secret); err != nil {
		return fmt.Errorf("LoadApp: %w", err)
	}
	le.Printf("Signer app loaded.\n")

	return nil
}

func (s *MultiAlgorithmSigner) printAuthorizedKey() {
	s.signer.printAuthorizedKey()
}

func (s *AlgorithmSigner) printAuthorizedKey() {
	s.signer.printAuthorizedKey()
}

func (s *Signer) printAuthorizedKey() {
	if !s.connect() {
		le.Printf("Connect failed")
		return
	}
	defer s.disconnect()

	pub, err := s.tkSigner.GetPubkey()
	if err != nil {
		le.Printf("GetPubkey failed: %s\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "len: %d\n", len(pub))
	str := hex.EncodeToString(pub)
	fmt.Fprintf(os.Stdout, "data: %s\n", str)

	var pubKey = rsa.PublicKey{}
	pubKey.N = &big.Int{}
	pubKey.N.SetBytes(pub)
	pubKey.E = 65537
	sshPub, err := ssh.NewPublicKey(&pubKey)

	if err != nil {
		le.Printf("NewPublicKey failed: %s\n", err)
		return
	}

	le.Printf("Your SSH public key (on stdout):\n")
	fmt.Fprintf(os.Stdout, "%s", ssh.MarshalAuthorizedKey(sshPub))
}

func (s *AlgorithmSigner) disconnect() {
	s.signer.disconnect()
}

func (s *Signer) disconnect() {
	if s.tkSigner == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected {
		return
	}

	if s.disconnectTimer != nil {
		s.disconnectTimer.Stop()
		s.disconnectTimer = nil
	}

	s.disconnectTimer = time.AfterFunc(idleDisconnect, func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.closeNow()
		s.connected = false
		s.disconnectTimer = nil
		le.Printf("Disconnected from TKey\n")
	})
}

func (s *MultiAlgorithmSigner) closeNow() {
	s.signer.closeNow()
}

func (s *AlgorithmSigner) closeNow() {
	s.signer.closeNow()
}

func (s *Signer) closeNow() {
	if s.tkSigner == nil {
		return
	}
	if err := s.tkSigner.Close(); err != nil {
		le.Printf("Close failed: %s\n", err)
	}
}
func (s *MultiAlgorithmSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}
func (s *AlgorithmSigner) PublicKey() ssh.PublicKey {
	key, err := ssh.NewPublicKey(s.signer.Public())
	if err != nil {
		panic("Cannot create public key")
	}
	return key
}

func (s *MultiAlgorithmSigner) Public() crypto.PublicKey {
	return s.signer.Public()
}

func (s *AlgorithmSigner) Public() crypto.PublicKey {
	return s.signer.Public()
}

// implementing crypto.Signer below
func (s *Signer) Public() crypto.PublicKey {
	if !s.connect() {
		return nil
	}
	defer s.disconnect()

	pub, err := s.tkSigner.GetPubkey()
	if err != nil {
		le.Printf("GetPubkey failed: %s\n", err)
		return nil
	}
	var pubKey = rsa.PublicKey{}
	pubKey.N = big.NewInt(0)
	pubKey.N.SetBytes(pub)
	pubKey.E = 65537

	return &pubKey
}

func (s *MultiAlgorithmSigner) Sign(reader io.Reader, message []byte) (*ssh.Signature, error) {
	return s.signer.Sign(reader, message)
}

func SwapEndianess(src []byte) []byte {
	output := make([]byte, len(src))
	for i := 0; i < len(src); i += 4 {
		output[i] = src[i+3]
		output[i+1] = src[i+2]
		output[i+2] = src[i+1]
		output[i+3] = src[i]
	}
	return output
}

func (s *AlgorithmSigner) Sign(reader io.Reader, message []byte) (*ssh.Signature, error) {
	debug.PrintStack()
	if !s.connect() {
		return nil, fmt.Errorf("Connect failed")
	}
	defer s.disconnect()

	signature, err := s.signer.tkSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}
	var sshSig = ssh.Signature{}
	prefix := "rsa-sha2-512"
	sshSig.Format = prefix
	sshSig.Blob = signature
	le.Println(len(sshSig.Blob))
	return &sshSig, nil
}

func (s *MultiAlgorithmSigner) Algorithms() []string {
	var algos = make([]string, 1)
	algos[0] = "rsa-sha2-512"
	return algos
}

func (s *MultiAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return s.signer.SignWithAlgorithm(rand, data, algorithm)
}

func (s *AlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm != "rsa-sha2-512" {
		return nil, fmt.Errorf("unsupported algo: %s", algorithm)
	}
	return s.Sign(rand, data)
}

func handleSignals(action func(), sig ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
}

// GetEmbeddedAppName returns the name of the embedded device app.
func GetEmbeddedAppName() string {
	return appName
}

// GetEmbeddedAppDigest returns a string of the SHA512 digest for the embedded
// device app
func GetEmbeddedAppDigest() string {
	digest := sha512.Sum512(appBinary)
	return hex.EncodeToString(digest[:])
}
